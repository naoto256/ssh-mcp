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
    AgentKey, AgentKeyList, ExecParams, ExecResult, GetParams, HostList, HostSummary,
    ProposeHostParams, ProposeHostResult, PutParams, SyncGetParams, SyncPutParams, SyncResult,
    TraceParams, TraceResult, TransferResult,
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
        description = "**DO NOT pipe through `tail` / `head` / `grep` in the shell command — use the `op` pipeline instead.** Shell-side pipes scope before the daemon sees the bytes, so `trace` only has the post-pipe slice; double-scoping triggers an advisory `note` on the result.\n\nRun a shell command on a host from list_hosts. Returns the exit code, line counts, and (optionally) the scoped output.\n\nExamples:\n  {\"host\": \"web1\", \"command\": \"uptime\"}\n      → run on web1, return metadata only (full output stays in the trace buffer)\n  {\"host\": \"web1\", \"command\": \"journalctl -u nginx\", \"op\": [{\"tail\": 50}]}\n      → last 50 lines of journalctl inline\n  {\"host\": \"web1\", \"command\": \"ls /var/log\", \"op\": [{\"grep\": \"\\\\.err$\"}]}\n      → only filenames ending in .err\n\n`op` is an ordered pipeline of steps applied to the command's combined output; omit it or pass `[]` to get metadata only (the full output stays in the per-session trace buffer for inspection through `trace`). To get the body inline, pass at least one step — same shape as `trace`: `{\"full\": true}`, `{\"head\": N}`, `{\"tail\": N}`, or `{\"grep\": \"STR\"}`. Chain steps for a sliding window, e.g. `[{\"head\": 100}, {\"tail\": 50}]` returns lines 51–100.\n\n**Shell semantics depend on the remote OS**: POSIX hosts run the command under the user's login shell (bash/sh/zsh as configured); Windows hosts run it under whatever OpenSSH has set as the default shell (typically PowerShell or cmd.exe — `;` or `&&` for sequencing, `$env:VAR` under PowerShell, `%VAR%` under cmd.exe). Output bytes come back in the remote console code page (UTF-8 on POSIX, whatever `chcp` reports on Windows: e.g. 932 = Shift_JIS, 437 = OEM US) and are decoded on the daemon side, so callers always see UTF-8 strings.\n\nEach call is stateless — no cwd or shell state carries over, use `cd /path && cmd`. Each call has a time limit (default 600s); for a longer-running job, start it detached and poll — e.g. `nohup sh -c 'long-cmd; echo $? > /tmp/job.rc' > /tmp/job.out 2>&1 &`, then read /tmp/job.rc later."
    )]
    async fn exec(&self, params: Parameters<ExecParams>) -> Result<Json<ExecResult>, String> {
        tools::exec::handle(self, params).await
    }

    #[tool(
        name = "trace",
        description = "Re-inspect the full detail of a recent tool call on this MCP session. The other tools return slim summaries to keep context lean; trace retrieves the body that backed them.\n\nExamples:\n  {\"op\": [{\"tail\": 30}]}\n      → last 30 lines of the most recent call (default index=0, stream=both)\n  {\"op\": [{\"grep\": \"error\"}], \"stream\": \"stderr\", \"index\": 1}\n      → stderr lines matching /error/ from the call before the most recent\n  {\"op\": [{\"head\": 200}, {\"tail\": 50}]}\n      → first 200 lines of the most recent call, then keep the last 50 of those\n        (i.e. a sliding window over lines 151–200)\n\n`op` is an ordered pipeline of steps applied to the recorded body; at least one step is required so the response stays deliberately scoped. Each step is exactly one of `{\"full\": true}`, `{\"head\": N}`, `{\"tail\": N}`, `{\"grep\": \"STR\"}`. The implicit start is the full body, so `[{\"full\": true}]` means \"give me everything\".\n\n`grep` matches the raw line text — never any `stdout:` / `stderr:` prefix — so a pattern that worked on the original `exec` result keeps working here.\n\n`stream` (default `both`) selects which channels of an `exec` entry to show: `both` prefixes each line with `stdout: ` / `stderr: ` and preserves arrival order; `stdout` or `stderr` returns only that channel with no prefix. Ignored for transfer entries.\n\n`index` selects which past call to look at: 0 = most recent (default), up to 4 — the buffer holds the last 5 calls per session.\n\nFor transfer entries, set `include_skipped` to mix the hash-matched (skipped) paths into the body. trace itself is not recorded."
    )]
    async fn trace(&self, params: Parameters<TraceParams>) -> Result<Json<TraceResult>, String> {
        tools::trace::handle(self, params).await
    }

    #[tool(
        name = "get",
        description = "Download a file or directory from a host to the local machine. Files and directories are both supported (the tool name omits 'file' because the same call covers both).\n\nExamples:\n  {\"host\": \"web1\", \"remote_path\": \"/etc/nginx/nginx.conf\", \"local_path\": \"~/nginx.conf\"}\n      → download a single file to a specific local path\n  {\"host\": \"web1\", \"remote_path\": \"logs/app.log\", \"local_path\": \"~/dl/\"}\n      → remote_path is relative to the login dir; local_path is an existing dir,\n        so the file lands as ~/dl/app.log\n  {\"host\": \"web1\", \"remote_path\": \"/var/www\", \"local_path\": \"~/site\",\n   \"exclude\": [\"*.log\", \"cache/\"]}\n      → download a directory tree, skipping logs and a cache subdir\n\n`remote_path` is on the host (absolute, or relative to the login directory — no leading `~`); `local_path` is where it lands locally (absolute, or starting with `~/`). If `local_path` is an existing directory the entry is placed inside it under its remote base name; otherwise `local_path` is replaced.\n\nThe host's configured exclude patterns are always skipped; pass `exclude` to add more globs for this call. Result is a byte count only — the full per-file detail is not returned; call `trace` if you need it. `bytes` is the total transferred over the wire including tar framing and metadata, not the sum of file content sizes."
    )]
    async fn get(&self, params: Parameters<GetParams>) -> Result<Json<TransferResult>, String> {
        tools::transfer::handle_get(self, params).await
    }

    #[tool(
        name = "put",
        description = "Upload a local file or directory to a host. Files and directories are both supported (the tool name omits 'file' because the same call covers both).\n\nExamples:\n  {\"host\": \"web1\", \"local_path\": \"~/deploy/site.tar.gz\", \"remote_path\": \"/tmp/site.tar.gz\"}\n      → upload a single file to a specific remote path\n  {\"host\": \"web1\", \"local_path\": \"~/build/app\", \"remote_path\": \"releases/\"}\n      → remote_path is relative to the login dir and is an existing dir, so the\n        file lands as releases/app\n  {\"host\": \"web1\", \"local_path\": \"~/src/project\", \"remote_path\": \"/srv/project\",\n   \"exclude\": [\"target/\", \"node_modules/\"]}\n      → upload a directory tree, skipping build output\n\n`local_path` is the local source (absolute, or starting with `~/`); `remote_path` is where it lands on the host (absolute, or relative to the login directory — no leading `~`). If `remote_path` is an existing directory the entry is placed inside it under its local base name; otherwise `remote_path` is replaced.\n\nThe inventory's configured exclude patterns (e.g. build output) are always skipped; pass `exclude` to add more globs for this call. Result is a byte count only — the full per-file detail is not returned; call `trace` if you need it. `bytes` is the total transferred over the wire including tar framing and metadata, not the sum of file content sizes."
    )]
    async fn put(&self, params: Parameters<PutParams>) -> Result<Json<TransferResult>, String> {
        tools::transfer::handle_put(self, params).await
    }

    #[tool(
        name = "sync_get",
        description = "Mirror a remote directory into a local location. Both paths are treated as roots — files on the local side that are absent from the remote source are deleted; files matching by sha256 are skipped.\n\nExamples:\n  {\"host\": \"web1\", \"remote_path\": \"/var/www/site\", \"local_path\": \"~/site\"}\n      → mirror /var/www/site → ~/site (creates ~/site if missing, deletes local\n        files not present remotely)\n  {\"host\": \"web1\", \"remote_path\": \"/var/log/app\", \"local_path\": \"~/logs\",\n   \"exclude\": [\"*.gz\"]}\n      → mirror while skipping rotated logs\n  // After a sync_get call, to see which files actually moved:\n  trace {\"op\": [{\"full\": true}], \"include_skipped\": true}\n      → lists `<verb> <path>` for created/updated/deleted (and skipped) entries\n\nThe remote source must be a directory; the local destination is created if missing. Returns per-op counts only (created/updated/deleted/skipped). **The per-file list is not in the result** — call `trace` to see which files moved (touched files appear as `<verb> <path>` lines; pass `include_skipped` to also see the hash-matched ones).\n\nThe host's configured exclude patterns are always skipped; pass `exclude` to add more globs for this call. `bytes` is the total transferred over the wire (only created/updated files were sent), including tar framing and metadata — not the sum of file content sizes."
    )]
    async fn sync_get(
        &self,
        params: Parameters<SyncGetParams>,
    ) -> Result<Json<SyncResult>, String> {
        tools::transfer::handle_sync_get(self, params).await
    }

    #[tool(
        name = "sync_put",
        description = "Mirror a local directory onto a host. Both paths are treated as roots — files on the remote that are absent from the local source are deleted; files matching by sha256 are skipped.\n\nExamples:\n  {\"host\": \"web1\", \"local_path\": \"~/site\", \"remote_path\": \"/var/www/site\"}\n      → mirror ~/site → /var/www/site (creates remote dir if missing, deletes\n        remote files not present locally)\n  {\"host\": \"web1\", \"local_path\": \"~/src/project\", \"remote_path\": \"/srv/project\",\n   \"exclude\": [\"target/\", \"node_modules/\"]}\n      → mirror while skipping build output\n  // After a sync_put call, to see which files actually moved:\n  trace {\"op\": [{\"full\": true}], \"include_skipped\": true}\n      → lists `<verb> <path>` for created/updated/deleted (and skipped) entries\n\nThe local source must be a directory; the remote destination is created if missing. Returns per-op counts only (created/updated/deleted/skipped). **The per-file list is not in the result** — call `trace` to see which files moved (touched files appear as `<verb> <path>` lines; pass `include_skipped` to also see the hash-matched ones).\n\nThe inventory's configured exclude patterns are always skipped; pass `exclude` to add more globs for this call. `bytes` is the total transferred over the wire (only created/updated files were sent), including tar framing and metadata — not the sum of file content sizes."
    )]
    async fn sync_put(
        &self,
        params: Parameters<SyncPutParams>,
    ) -> Result<Json<SyncResult>, String> {
        tools::transfer::handle_sync_put(self, params).await
    }

    #[tool(
        name = "propose_host",
        description = "Append a *pending* host entry to the user's ssh-hosts.toml so they can review and activate it.\n\nThe tool exists for the common case where the user has just spun up an Azure / AWS VM and wants Claude to start using it without typing the TOML by hand. **Calling this tool does NOT make the host usable** — the entry is written with `disabled = true` and the user must open the file and remove that line (or set it to false) for the daemon to pick the host up on the next call. That hand edit is the trust gate.\n\nExamples:\n  {\"hostname\": \"13.78.10.5\", \"user\": \"azureuser\", \"purpose\": \"azure scratch box\",\n   \"expires_at\": \"2026-05-27T19:30:00+09:00\",\n   \"host_key\": \"ssh-ed25519 AAAAC3Nz... host@vm\"}\n      → write [hosts.tmp-XXXXXX] with policy=[\"claude\"], disabled=true,\n        the pinned host_key, and expires_at as given; tell the user to flip\n        `disabled`.\n  {\"hostname\": \"10.0.5.7\", \"user\": \"ubuntu\", \"purpose\": \"jump from bastion\",\n   \"expires_at\": \"2026-05-26T09:00:00+09:00\",\n   \"host_key\": \"ssh-ed25519 AAAAC3Nz... host@vm\",\n   \"proxy_jump\": [\"bastion\"], \"tags\": [\"db\"]}\n      → same shape, plus a jump chain and tags.\n\nServer-controlled fields the caller cannot set: `alias` (auto-generated as `tmp-` plus 6 random hex chars), `policy` (hard-coded to `[\"claude\"]` — adjust by hand if a stricter gate is needed), `disabled` (always true on write).\n\nRequired fields: `hostname`, `user`, `purpose`, `expires_at`, `host_key`. `expires_at` must be a RFC 3339 datetime in the future, at most 30 days out — the daemon GCs expired entries from the TOML at load time. `host_key` is the OpenSSH-format public key the daemon will pin for this host (verified instead of `~/.ssh/known_hosts`); harvest it from the cloud provider's console or by running `ssh-keyscan` via `exec`. `proxy_jump` aliases must already exist as active hosts."
    )]
    async fn propose_host(
        &self,
        params: Parameters<ProposeHostParams>,
    ) -> Result<Json<ProposeHostResult>, String> {
        tools::propose_host::handle(self, params).await
    }

    #[tool(
        name = "list_agent_keys",
        description = "List the public keys currently held by the user's SSH agent ($SSH_AUTH_SOCK). Equivalent to `ssh-add -L`. Use this when you need to tell the user which key to register with a freshly provisioned host (paste one of the `public_key` strings into the host's `authorized_keys`), or to diagnose why an `exec` call fails with \"SSH agent authentication failed\".\n\nExamples:\n  {}\n      → list every identity loaded into the agent\n\nReturns one entry per identity, each with `type`, `comment`, `fingerprint` (SHA-256), and the full OpenSSH `public_key` line. Certificates are not included. No arguments."
    )]
    async fn list_agent_keys(&self) -> Result<Json<AgentKeyList>, String> {
        tools::list_agent_keys::handle(self).await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ssh-mcp", env!("CARGO_PKG_VERSION")))
    }
}
