//! The MCP server the daemon runs over each UDS connection.
//!
//! `list_hosts` shows the curated inventory — purpose and policy only, never
//! an address or credentials. `exec` runs a command. `get` and `put` transfer
//! a single file or directory (`cp` semantics on the destination); `sync_get`
//! and `sync_put` mirror a directory in either direction (per-entry policy
//! against the change set). `trace` retrieves the full detail of a recent
//! call from a per-session ring buffer, since the other tools return
//! summarized results to keep the model's context lean. Policy is not
//! evaluated here: by the time a call reaches the daemon the hook has
//! already approved it.
//!
//! ## Layout
//!
//! `types` holds every wire struct (`*Params` / `*Result` / `HostSummary`
//! etc.) so the schema surface is readable in one file. `tools::<tool>`
//! holds each handler body as a `pub(in crate::mcp) async fn handle(...)`
//! free function. The `#[tool_router]` impl below keeps the rmcp-required
//! `#[tool]` methods (one per tool) collected in a single impl block —
//! each method is a thin delegator to its `tools::<tool>::handle`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{Json, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use tokio::net::UnixStream;

use crate::audit::AuditLog;
use crate::ssh::ConnectionPool;
use crate::trace::{DEFAULT_TRACE_DEPTH, TraceBuffer};

mod tools;
pub mod types;

pub use types::{
    ExecParams, ExecResult, GetParams, HostList, HostSummary, PutParams, SyncGetParams,
    SyncPutParams, SyncResult, TraceParams, TraceResult, TransferResult,
};

/// One MCP session's view of the daemon. Cheap to clone — it shares the
/// daemon's connection pool and the per-session trace buffer, and adds the
/// per-session tool router.
///
/// Fields are `pub(in crate::mcp)` so the per-tool handler modules in
/// `tools::*` can read them directly; nothing outside this module tree
/// needs the internals.
#[derive(Clone)]
pub struct SshMcpServer {
    pub(in crate::mcp) pool: Arc<ConnectionPool>,
    pub(in crate::mcp) config_path: PathBuf,
    pub(in crate::mcp) audit: AuditLog,
    pub(in crate::mcp) trace: TraceBuffer,
    tool_router: ToolRouter<Self>,
}

#[tool_router(router = tool_router)]
impl SshMcpServer {
    /// Build a session that shares the daemon's connection pool and audit log
    /// and owns a fresh trace buffer for its own tool calls.
    pub fn new(pool: Arc<ConnectionPool>, config_path: PathBuf, audit: AuditLog) -> Self {
        Self {
            pool,
            config_path,
            audit,
            trace: TraceBuffer::new(DEFAULT_TRACE_DEPTH),
            tool_router: Self::tool_router(),
        }
    }

    /// Serve one MCP session over a connection until the client disconnects.
    pub async fn serve_connection(self, stream: UnixStream) -> Result<()> {
        let running = self
            .serve(stream)
            .await
            .context("the MCP session handshake failed")?;
        running
            .waiting()
            .await
            .context("the MCP session ended with an error")?;
        Ok(())
    }

    #[tool(
        name = "list_hosts",
        description = "List the SSH hosts available to run commands on. Each entry has an alias, its purpose, tags, and the policy gating it — never an address or credentials. Choose a host by purpose, then call exec with its alias."
    )]
    async fn list_hosts(&self) -> Result<Json<HostList>, String> {
        tools::list_hosts::handle(self).await
    }

    #[tool(
        name = "exec",
        description = "**DO NOT pipe through `tail` / `head` / `grep` in the shell command — use the `op` pipeline instead.** Shell-side pipes scope before the daemon sees the bytes, so `trace` only has the post-pipe slice; double-scoping triggers an advisory `note` on the result.\n\nRun a shell command on a host from list_hosts. Returns the exit code, line counts, and (optionally) the scoped output. **Shell semantics depend on the remote OS**: POSIX hosts run the command under the user's login shell (bash/sh/zsh as configured); Windows hosts run it under whatever OpenSSH has set as the default shell (typically PowerShell or cmd.exe — `;` or `&&` for sequencing, `$env:VAR` under PowerShell, `%VAR%` under cmd.exe). Output bytes come back in the remote console code page (UTF-8 on POSIX, whatever `chcp` reports on Windows: e.g. 932 = Shift_JIS, 437 = OEM US) and are decoded on the daemon side, so callers always see UTF-8 strings. `op` is an ordered pipeline of steps — omit it or pass `[]` to get the metadata only (the full output stays in the per-session trace buffer for inspection through `trace`). To get the body inline, pass at least one step: `[{full: true}]` for everything, `[{tail: 50}]` for the last 50 lines, `[{grep: \"err\"}]` for matches, or chain — `[{head: 100}, {tail: 50}]` is a sliding window from line 51 to 100. Steps apply in order; the implicit start is the full body. Each call is stateless (no cwd or shell state carries over, use `cd /path && cmd`). Each call has a time limit (default 600s); for a longer-running job, start it detached and poll — e.g. \"nohup sh -c 'long-cmd; echo $? > /tmp/job.rc' > /tmp/job.out 2>&1 &\", then read /tmp/job.rc later."
    )]
    async fn exec(&self, params: Parameters<ExecParams>) -> Result<Json<ExecResult>, String> {
        tools::exec::handle(self, params).await
    }

    #[tool(
        name = "trace",
        description = "Re-inspect the full detail of a recent tool call on this MCP session. The other tools return slim summaries to keep context lean; trace retrieves the body that backed them. The `op` parameter is an ordered pipeline of steps — at least one step is required so the response stays deliberately scoped. Each step is one of `{full: true}`, `{head: N}`, `{tail: N}`, `{grep: STR}`; steps apply in order, with the implicit start being the full body. For example `[{full: true}]` returns everything, `[{tail: 50}]` the last 50, `[{grep: \"err\"}]` matching lines, and `[{head: 100}, {tail: 50}, {grep: \"x\"}]` reads the first 100, keeps the last 50 of those, then greps. `grep` matches the raw line text — never any `stdout:` / `stderr:` prefix — so a pattern that worked on the original `exec` result keeps working here. `stream` (default `both`) selects which channels of an `exec` entry to show: `both` prefixes each line with `stdout: ` or `stderr: ` and preserves the arrival order; `stdout` or `stderr` returns only that channel with no prefix. `stream` is ignored for transfer entries. `index` selects which past call to look at: 0 is the most recent (default), 1 the one before that, up to 4 — the buffer holds the last 5 calls per session. For transfer entries, set `include_skipped` to mix the hash-matched (skipped) paths into the body. trace itself is not recorded."
    )]
    async fn trace(&self, params: Parameters<TraceParams>) -> Result<Json<TraceResult>, String> {
        tools::trace::handle(self, params).await
    }

    #[tool(
        name = "get",
        description = "Download a file or directory from a host to the local machine. Files and directories are both supported (the tool name omits 'file' because the same call covers both). remote_path is on the host (absolute, or relative to the login directory — no leading ~); local_path is where it lands locally (absolute, or starting with ~/). If local_path is an existing directory the entry is placed inside it under its remote base name; otherwise local_path is replaced. The host's configured exclude patterns are always skipped; pass exclude to add more globs for this call. Result is a byte count only — the full per-file detail is not returned; call trace if you need it. `bytes` is the total transferred over the wire including tar framing and metadata, not the sum of file content sizes."
    )]
    async fn get(&self, params: Parameters<GetParams>) -> Result<Json<TransferResult>, String> {
        tools::transfer::handle_get(self, params).await
    }

    #[tool(
        name = "put",
        description = "Upload a local file or directory to a host. Files and directories are both supported (the tool name omits 'file' because the same call covers both). local_path is the local source (absolute, or starting with ~/); remote_path is where it lands on the host (absolute, or relative to the login directory — no leading ~). If remote_path is an existing directory the entry is placed inside it under its local base name; otherwise remote_path is replaced. The inventory's configured exclude patterns (e.g. build output) are always skipped; pass exclude to add more globs for this call. Result is a byte count only — the full per-file detail is not returned; call trace if you need it. `bytes` is the total transferred over the wire including tar framing and metadata, not the sum of file content sizes."
    )]
    async fn put(&self, params: Parameters<PutParams>) -> Result<Json<TransferResult>, String> {
        tools::transfer::handle_put(self, params).await
    }

    #[tool(
        name = "sync_get",
        description = "Mirror a remote directory into a local location. Both paths are treated as roots — files on the local side that are absent from the remote source are deleted; files matching by sha256 are skipped. The remote source must be a directory; the local destination is created if missing. Returns per-op counts only (created/updated/deleted/skipped). **The per-file list is not in the result** — to see which files moved, call `trace` (the touched files come back as `<verb> <path>` lines; pass `include_skipped` to also see the hash-matched ones). The host's configured exclude patterns are always skipped; pass exclude to add more globs for this call. `bytes` is the total transferred over the wire (only created/updated files were sent), including tar framing and metadata — not the sum of file content sizes."
    )]
    async fn sync_get(
        &self,
        params: Parameters<SyncGetParams>,
    ) -> Result<Json<SyncResult>, String> {
        tools::transfer::handle_sync_get(self, params).await
    }

    #[tool(
        name = "sync_put",
        description = "Mirror a local directory onto a host. Both paths are treated as roots — files on the remote that are absent from the local source are deleted; files matching by sha256 are skipped. The local source must be a directory; the remote destination is created if missing. Returns per-op counts only (created/updated/deleted/skipped). **The per-file list is not in the result** — to see which files moved, call `trace` (the touched files come back as `<verb> <path>` lines; pass `include_skipped` to also see the hash-matched ones). The inventory's configured exclude patterns are always skipped; pass exclude to add more globs for this call. `bytes` is the total transferred over the wire (only created/updated files were sent), including tar framing and metadata — not the sum of file content sizes."
    )]
    async fn sync_put(
        &self,
        params: Parameters<SyncPutParams>,
    ) -> Result<Json<SyncResult>, String> {
        tools::transfer::handle_sync_put(self, params).await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ssh-mcp", env!("CARGO_PKG_VERSION")))
    }
}
