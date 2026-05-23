//! The MCP server the daemon runs over each UDS connection.
//!
//! `list_hosts` shows the curated inventory — purpose and policy only, never
//! an address or credentials. `exec` runs a command. `get_file` / `put_file`
//! transfer files and directories. `trace` retrieves the full detail of a
//! recent call from a per-session ring buffer, since the other tools return
//! summarized results to keep the model's context lean. Policy is not
//! evaluated here: by the time a call reaches the daemon the hook has
//! already approved it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{Json, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

use crate::audit::AuditLog;
use crate::config::HostsConfig;
use crate::pathnorm;
use crate::ssh::ConnectionPool;
use crate::trace::{DEFAULT_TRACE_DEPTH, Op, TraceBuffer, TraceEntry};

/// A host as shown to the model: what it is for and how it is gated, never
/// its address or credentials.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct HostSummary {
    /// The logical name to pass to `exec`.
    pub alias: String,
    /// What the host is used for.
    pub purpose: String,
    /// Free-form tags for filtering.
    pub tags: Vec<String>,
    /// The policy gates guarding the host: `free`, `def`, `claude`, or `hook`.
    pub policy: Vec<String>,
}

/// The `list_hosts` result. The list is wrapped in an object because an MCP
/// tool's output schema must have an object at its root.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct HostList {
    pub hosts: Vec<HostSummary>,
}

/// Arguments to `exec`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ExecParams {
    /// The host alias, as returned by `list_hosts`.
    pub host: String,
    /// The shell command to run on the host.
    pub command: String,
    /// Output scope, applied to stdout and stderr before they are returned.
    /// At least one of `grep`, `head`, or `tail` is required so the model
    /// cannot accidentally request an unscoped dump. The full output is
    /// retained by the daemon and can be re-scoped with `trace`.
    pub op: Op,
}

/// The result of `exec`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ExecResult {
    pub exit_code: i32,
    /// stdout lines kept after the `op` was applied.
    pub stdout: Vec<String>,
    /// Total number of stdout lines produced, before the `op` filtered any
    /// out. `stdout.len()` is the kept count.
    pub stdout_lines: u32,
    /// stderr lines kept after the `op` was applied.
    pub stderr: Vec<String>,
    /// Total number of stderr lines produced, before the `op` filtered any
    /// out. `stderr.len()` is the kept count.
    pub stderr_lines: u32,
}

/// Arguments to `trace`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TraceParams {
    /// Which past call to look at: 0 = the most recent, 1 = the one before
    /// that, and so on. Defaults to the most recent.
    #[serde(default)]
    pub index: u32,
    /// Output scope, applied to the recorded body before it is returned.
    /// At least one of `grep`, `head`, or `tail` is required.
    pub op: Op,
    /// For transfer entries, mix the skipped (hash-matched) paths into the
    /// body before the `op` is applied. Ignored for `exec` entries.
    #[serde(default)]
    pub include_skipped: bool,
}

/// The result of `trace`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TraceResult {
    /// The tool whose call this trace refers to (`"exec"`, `"get_file"`, ...).
    pub tool: String,
    /// Human-readable parameter summary of the original call.
    pub params: String,
    /// Human-readable result summary of the original call.
    pub summary: String,
    /// Body lines kept after the `op` was applied. For `exec` each line is
    /// channel-tagged (`"stdout: ..."` / `"stderr: ..."`); for transfers each
    /// line is op-tagged (`"create <path>"` / `"update <path>"` /
    /// `"delete <path>"` / `"skip <path>"`).
    pub lines: Vec<String>,
    /// Total number of body lines available before the `op` filtered any
    /// out. `lines.len()` is the kept count.
    pub total_lines: u32,
    /// Set when the originating tool's body exceeded the per-entry byte cap
    /// and the buffer dropped the tail.
    pub truncated: bool,
}

/// Arguments to `get_file`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct GetFileParams {
    /// The host alias, as returned by `list_hosts`.
    pub host: String,
    /// The path on the host to download — absolute, or relative to the login
    /// directory, without a leading `~`.
    pub remote_path: String,
    /// Where to place it locally — absolute, or starting with `~/`.
    pub local_path: String,
    /// Optional glob patterns to skip, added to the host's configured
    /// exclude — a pattern matches a file or directory name anywhere in the
    /// tree, e.g. "target", ".git", "*.log".
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Arguments to `put_file`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PutFileParams {
    /// The host alias, as returned by `list_hosts`.
    pub host: String,
    /// The local path to upload — absolute, or starting with `~/`.
    pub local_path: String,
    /// Where to place it on the host — absolute, or relative to the login
    /// directory, without a leading `~`.
    pub remote_path: String,
    /// Optional glob patterns to skip, added to the inventory's configured
    /// exclude — a pattern matches a file or directory name anywhere in the
    /// tree, e.g. "target", ".git", "*.log".
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// The result of a transfer.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TransferResult {
    /// The number of bytes transferred.
    pub bytes: u64,
}

/// The result of a `sync_get` / `sync_put` call: archive payload size plus
/// per-op counts derived from the change set. The full per-file list is
/// kept in the trace buffer; call `trace` to drill in.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SyncResult {
    pub bytes: u64,
    pub created: u32,
    pub updated: u32,
    pub deleted: u32,
    pub skipped: u32,
}

/// One MCP session's view of the daemon. Cheap to clone — it shares the
/// daemon's connection pool and the per-session trace buffer, and adds the
/// per-session tool router.
#[derive(Clone)]
pub struct SshMcpServer {
    pool: Arc<ConnectionPool>,
    config_path: PathBuf,
    audit: AuditLog,
    trace: TraceBuffer,
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
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        let mut hosts: Vec<HostSummary> = config
            .hosts
            .iter()
            .map(|(alias, entry)| HostSummary {
                alias: alias.clone(),
                purpose: entry.purpose.clone(),
                tags: entry.tags.clone(),
                policy: entry
                    .policy
                    .iter()
                    .map(|gate| gate.kind().to_string())
                    .collect(),
            })
            .collect();
        hosts.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(Json(HostList { hosts }))
    }

    #[tool(
        name = "exec",
        description = "Run a shell command on a host from list_hosts and return its exit code with op-scoped stdout/stderr. Each call is stateless — no working directory or shell state carries to the next call, so use 'cd /path && cmd' when a directory matters. The op parameter is required: pass tail/head/grep so the returned slice is deliberately scoped. **Do not also pipe through tail/head/grep in the shell command** — op is the canonical scope, and the full unscoped stdout/stderr is retained in the per-session trace buffer so you can re-scope through `trace` later. Double-scoping defeats the trace path: it throws away the very output you might want to inspect with a different filter. Each call has a time limit (default 600s); for a longer-running job, start it detached and poll for completion — e.g. \"nohup sh -c 'long-cmd; echo $? > /tmp/job.rc' > /tmp/job.out 2>&1 &\", then read /tmp/job.rc on later calls."
    )]
    async fn exec(&self, params: Parameters<ExecParams>) -> Result<Json<ExecResult>, String> {
        let ExecParams { host, command, op } = params.0;
        op.validate()?;
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        let timeout = match config.host(&host) {
            Some(entry) => Duration::from_secs(config.exec_timeout_secs(entry)),
            None => return Err(format!("unknown host {host:?}")),
        };

        let result = self.pool.exec(&config, &host, &command, timeout).await;
        match &result {
            Ok(output) => self
                .audit
                .record_exec(&host, &command, Some(output.exit_code), None),
            Err(error) => {
                let message = format!("{error:#}");
                self.audit
                    .record_exec(&host, &command, None, Some(&message));
            }
        }

        let output = result.map_err(|e| format!("{e:#}"))?;
        let stdout_all: Vec<String> = output.stdout.lines().map(String::from).collect();
        let stderr_all: Vec<String> = output.stderr.lines().map(String::from).collect();

        // The trace buffer holds the channel-tagged full body — the
        // unfiltered record the model can re-scope later — independently of
        // what the op chooses to surface this turn.
        let mut body = Vec::with_capacity(stdout_all.len() + stderr_all.len());
        for line in &stdout_all {
            body.push(format!("stdout: {line}"));
        }
        for line in &stderr_all {
            body.push(format!("stderr: {line}"));
        }
        let trace_summary = format!(
            "exit={} stdout_lines={} stderr_lines={}",
            output.exit_code,
            stdout_all.len(),
            stderr_all.len()
        );
        self.trace
            .record(TraceEntry {
                tool: "exec".into(),
                params: format!("host={host:?} command={command:?}"),
                summary: trace_summary,
                lines: body,
                skipped: vec![],
                truncated: false,
            })
            .await;

        let (stdout, stdout_lines) = op.apply(stdout_all)?;
        let (stderr, stderr_lines) = op.apply(stderr_all)?;
        Ok(Json(ExecResult {
            exit_code: output.exit_code,
            stdout,
            stdout_lines,
            stderr,
            stderr_lines,
        }))
    }

    #[tool(
        name = "trace",
        description = "Re-inspect the full detail of a recent tool call on this MCP session. The other tools return slim summaries to keep context lean; trace retrieves the body that backed them. The op parameter is required (tail/head/grep, with grep applied before head/tail) so output stays scoped. index selects which past call to look at: 0 is the most recent (default), 1 the one before that, up to 4 — the buffer holds the last 5 calls per session. For transfer entries, set include_skipped to mix the hash-matched (skipped) paths into the body. trace itself is not recorded."
    )]
    async fn trace(&self, params: Parameters<TraceParams>) -> Result<Json<TraceResult>, String> {
        let TraceParams {
            index,
            op,
            include_skipped,
        } = params.0;
        op.validate()?;
        let entry = self
            .trace
            .fetch(index as usize)
            .await
            .ok_or_else(|| format!("no trace entry at index {index}"))?;
        let mut body = entry.lines.clone();
        if include_skipped {
            body.extend(entry.skipped.iter().cloned());
        }
        let (lines, total_lines) = op.apply(body)?;
        Ok(Json(TraceResult {
            tool: entry.tool,
            params: entry.params,
            summary: entry.summary,
            lines,
            total_lines,
            truncated: entry.truncated,
        }))
    }

    #[tool(
        name = "get_file",
        description = "Download a file or directory from a host to the local machine. remote_path is on the host (absolute, or relative to the login directory — no leading ~); local_path is where it lands locally (absolute, or starting with ~/). If local_path is an existing directory the entry is placed inside it under its remote base name; otherwise local_path is replaced. Files and directories are both supported. The host's configured exclude patterns are always skipped; pass exclude to add more globs for this call. Result is a byte count only — the full per-file detail is not returned; call trace if you need it."
    )]
    async fn get_file(
        &self,
        params: Parameters<GetFileParams>,
    ) -> Result<Json<TransferResult>, String> {
        let GetFileParams {
            host,
            remote_path,
            local_path,
            exclude,
        } = params.0;
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        // The download exclude is per-host (the remote tree is host-specific);
        // the tool argument adds more for this call.
        let (timeout, mut excludes) = match config.host(&host) {
            Some(entry) => (
                Duration::from_secs(config.exec_timeout_secs(entry)),
                entry.exclude.clone(),
            ),
            None => return Err(format!("unknown host {host:?}")),
        };
        excludes.extend(exclude);
        // Normalize exactly as the policy gate did, so the two cannot disagree.
        let remote = pathnorm::normalize_remote(&remote_path).map_err(|e| format!("{e:#}"))?;
        let local = pathnorm::normalize_local(&local_path).map_err(|e| format!("{e:#}"))?;

        let result = self
            .pool
            .get_file(&config, &host, &remote, &local, &excludes, timeout)
            .await;
        let local_display = local.to_string_lossy();
        match &result {
            Ok(stats) => self.audit.record_transfer(
                "get",
                &host,
                &remote,
                &local_display,
                Some(stats.bytes),
                None,
            ),
            Err(error) => {
                let message = format!("{error:#}");
                self.audit.record_transfer(
                    "get",
                    &host,
                    &remote,
                    &local_display,
                    None,
                    Some(&message),
                );
            }
        }

        let stats = result.map_err(|e| format!("{e:#}"))?;
        Ok(Json(TransferResult { bytes: stats.bytes }))
    }

    #[tool(
        name = "sync_get",
        description = "Mirror a remote directory into a local location. Both paths are treated as roots — files on the local side that are absent from the remote source are deleted; files matching by sha256 are skipped. The remote source must be a directory; the local destination is created if missing. Returns per-op counts only (created/updated/deleted/skipped). **The per-file list is not in the result** — to see which files moved, call `trace` (the touched files come back as `<verb> <path>` lines; pass `include_skipped` to also see the hash-matched ones). The host's configured exclude patterns are always skipped; pass exclude to add more globs for this call."
    )]
    async fn sync_get(
        &self,
        params: Parameters<GetFileParams>,
    ) -> Result<Json<SyncResult>, String> {
        let GetFileParams {
            host,
            remote_path,
            local_path,
            exclude,
        } = params.0;
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        let (timeout, mut excludes) = match config.host(&host) {
            Some(entry) => (
                Duration::from_secs(config.exec_timeout_secs(entry)),
                entry.exclude.clone(),
            ),
            None => return Err(format!("unknown host {host:?}")),
        };
        excludes.extend(exclude);
        let remote = pathnorm::normalize_remote(&remote_path).map_err(|e| format!("{e:#}"))?;
        let local = pathnorm::normalize_local(&local_path).map_err(|e| format!("{e:#}"))?;

        let result = self
            .pool
            .sync_get(&config, &host, &remote, &local, &excludes, timeout)
            .await;
        let local_display = local.to_string_lossy();
        match &result {
            Ok(sr) => self.audit.record_transfer(
                "sync_get",
                &host,
                &remote,
                &local_display,
                Some(sr.bytes),
                None,
            ),
            Err(error) => {
                let message = format!("{error:#}");
                self.audit.record_transfer(
                    "sync_get",
                    &host,
                    &remote,
                    &local_display,
                    None,
                    Some(&message),
                );
            }
        }
        let sr = result.map_err(|e| format!("{e:#}"))?;
        let counts = sr.change_set.counts();
        self.record_transfer_trace("sync_get", &host, &remote, &local_display, &sr)
            .await;
        Ok(Json(SyncResult {
            bytes: sr.bytes,
            created: counts.created,
            updated: counts.updated,
            deleted: counts.deleted,
            skipped: counts.skipped,
        }))
    }

    #[tool(
        name = "sync_put",
        description = "Mirror a local directory onto a host. Both paths are treated as roots — files on the remote that are absent from the local source are deleted; files matching by sha256 are skipped. The local source must be a directory; the remote destination is created if missing. Returns per-op counts only (created/updated/deleted/skipped). **The per-file list is not in the result** — to see which files moved, call `trace` (the touched files come back as `<verb> <path>` lines; pass `include_skipped` to also see the hash-matched ones). The inventory's configured exclude patterns are always skipped; pass exclude to add more globs for this call."
    )]
    async fn sync_put(
        &self,
        params: Parameters<PutFileParams>,
    ) -> Result<Json<SyncResult>, String> {
        let PutFileParams {
            host,
            local_path,
            remote_path,
            exclude,
        } = params.0;
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        let timeout = match config.host(&host) {
            Some(entry) => Duration::from_secs(config.exec_timeout_secs(entry)),
            None => return Err(format!("unknown host {host:?}")),
        };
        let remote = pathnorm::normalize_remote(&remote_path).map_err(|e| format!("{e:#}"))?;
        let local = pathnorm::normalize_local(&local_path).map_err(|e| format!("{e:#}"))?;

        let mut excludes = config.defaults.exclude.clone();
        excludes.extend(exclude);

        let result = self
            .pool
            .sync_put(&config, &host, &local, &remote, &excludes, timeout)
            .await;
        let local_display = local.to_string_lossy();
        match &result {
            Ok(sr) => self.audit.record_transfer(
                "sync_put",
                &host,
                &remote,
                &local_display,
                Some(sr.bytes),
                None,
            ),
            Err(error) => {
                let message = format!("{error:#}");
                self.audit.record_transfer(
                    "sync_put",
                    &host,
                    &remote,
                    &local_display,
                    None,
                    Some(&message),
                );
            }
        }
        let sr = result.map_err(|e| format!("{e:#}"))?;
        let counts = sr.change_set.counts();
        self.record_transfer_trace("sync_put", &host, &remote, &local_display, &sr)
            .await;
        Ok(Json(SyncResult {
            bytes: sr.bytes,
            created: counts.created,
            updated: counts.updated,
            deleted: counts.deleted,
            skipped: counts.skipped,
        }))
    }

    /// Build the line-oriented trace body for a transfer (`<op> <rel_path>`
    /// per line; the skipped paths are stashed separately so the model can
    /// opt in to them through `include_skipped`).
    async fn record_transfer_trace(
        &self,
        tool: &str,
        host: &str,
        remote: &str,
        local: &str,
        sr: &crate::ssh::SyncResult,
    ) {
        let mut lines = Vec::new();
        let mut skipped = Vec::new();
        for entry in &sr.change_set.entries {
            let line = format!("{} {}", entry.op.verb(), entry.rel_path.display());
            if entry.op == crate::changeset::ChangeOp::Skip {
                skipped.push(line);
            } else {
                lines.push(line);
            }
        }
        let counts = sr.change_set.counts();
        let summary = format!(
            "bytes={} created={} updated={} deleted={} skipped={}",
            sr.bytes, counts.created, counts.updated, counts.deleted, counts.skipped
        );
        self.trace
            .record(TraceEntry {
                tool: tool.into(),
                params: format!("host={host:?} remote={remote:?} local={local:?}"),
                summary,
                lines,
                skipped,
                truncated: false,
            })
            .await;
    }

    #[tool(
        name = "put_file",
        description = "Upload a local file or directory to a host. local_path is the local source (absolute, or starting with ~/); remote_path is where it lands on the host (absolute, or relative to the login directory — no leading ~). If remote_path is an existing directory the entry is placed inside it under its local base name; otherwise remote_path is replaced. Files and directories are both supported. The inventory's configured exclude patterns (e.g. build output) are always skipped; pass exclude to add more globs for this call. Result is a byte count only — the full per-file detail is not returned; call trace if you need it."
    )]
    async fn put_file(
        &self,
        params: Parameters<PutFileParams>,
    ) -> Result<Json<TransferResult>, String> {
        let PutFileParams {
            host,
            local_path,
            remote_path,
            exclude,
        } = params.0;
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        let timeout = match config.host(&host) {
            Some(entry) => Duration::from_secs(config.exec_timeout_secs(entry)),
            None => return Err(format!("unknown host {host:?}")),
        };
        let remote = pathnorm::normalize_remote(&remote_path).map_err(|e| format!("{e:#}"))?;
        let local = pathnorm::normalize_local(&local_path).map_err(|e| format!("{e:#}"))?;

        // The upload exclude is global (the source tree's property, not the
        // host's); the tool argument adds more for this call.
        let mut excludes = config.defaults.exclude.clone();
        excludes.extend(exclude);

        let result = self
            .pool
            .put_file(&config, &host, &local, &remote, &excludes, timeout)
            .await;
        let local_display = local.to_string_lossy();
        match &result {
            Ok(stats) => self.audit.record_transfer(
                "put",
                &host,
                &remote,
                &local_display,
                Some(stats.bytes),
                None,
            ),
            Err(error) => {
                let message = format!("{error:#}");
                self.audit.record_transfer(
                    "put",
                    &host,
                    &remote,
                    &local_display,
                    None,
                    Some(&message),
                );
            }
        }

        let stats = result.map_err(|e| format!("{e:#}"))?;
        Ok(Json(TransferResult { bytes: stats.bytes }))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ssh-mcp", env!("CARGO_PKG_VERSION")))
    }
}
