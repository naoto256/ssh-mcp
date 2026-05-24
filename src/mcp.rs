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
use crate::trace::{
    Channel, DEFAULT_TRACE_DEPTH, OpStep, Stream, TraceBuffer, TraceEntry, TraceLine,
    apply_pipeline, apply_tagged_pipeline, chunks_to_lines, validate_pipeline,
};

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
    /// Output scope as an ordered pipeline of steps. Omit or pass an empty
    /// array to skip returning stdout/stderr entirely — the result then
    /// carries just the exit code and counts, and the full output stays in
    /// the trace buffer for later inspection through `trace`. To get the
    /// body inline, pass at least one step: `[{full: true}]` for
    /// everything, `[{tail: 50}]` for the last 50, `[{grep: "err"}]` for
    /// matching lines, or chain — `[{head: 100}, {tail: 50}, {grep: "x"}]`
    /// reads the first 100, then keeps the last 50 of those (a sliding
    /// window from line 51 to 100), then greps. The implicit starting
    /// point is the full body, so `{full: true}` only needs to be written
    /// when it's the lone step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub op: Vec<OpStep>,
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
    /// Advisory note from the daemon. Currently emitted when the command's
    /// last unquoted pipe targets a line-scoping program (`tail`, `head`,
    /// `grep`, `egrep`, `fgrep`, `rg`) — the shell will have already
    /// dropped everything past that pipe, so the trace buffer only holds
    /// the post-pipe slice. Pass the scope through `op` instead and let
    /// `trace` re-scope from the full stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Arguments to `trace`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TraceParams {
    /// Which past call to look at: 0 = the most recent, 1 = the one before
    /// that, and so on. Defaults to the most recent.
    #[serde(default)]
    pub index: u32,
    /// Output scope as an ordered pipeline of steps, applied to the
    /// recorded body. At least one step is required (an empty pipeline is
    /// rejected — call `exec` with an empty op if you only want metadata).
    /// Each step is one of `{full: true}`, `{head: N}`, `{tail: N}`, or
    /// `{grep: STR}`; chain them to compose. `grep` matches the raw line
    /// text — never the `stdout:` / `stderr:` prefix — so a pattern that
    /// worked on the original `exec` result keeps working here.
    pub op: Vec<OpStep>,
    /// Which channels of an `exec` entry to surface. Defaults to `both`
    /// (channel-prefixed output, arrival order preserved). Set to `stdout`
    /// or `stderr` to look at one channel with no prefix. Ignored for
    /// transfer entries — their lines pass through every selector.
    #[serde(default)]
    pub stream: Stream,
    /// For transfer entries, mix the skipped (hash-matched) paths into the
    /// body before the `op` is applied. Ignored for `exec` entries.
    #[serde(default)]
    pub include_skipped: bool,
}

/// The result of `trace`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TraceResult {
    /// The tool whose call this trace refers to (`"exec"`, `"get"`, `"put"`,
    /// `"sync_get"`, `"sync_put"`).
    pub tool: String,
    /// Human-readable parameter summary of the original call.
    pub params: String,
    /// Human-readable result summary of the original call.
    pub summary: String,
    /// Body lines kept after the `op` was applied. For `exec` entries with
    /// `stream = "both"` (the default) each line is channel-prefixed
    /// (`"stdout: ..."` / `"stderr: ..."`) and the arrival order is
    /// preserved; for `stream = "stdout"` or `"stderr"` the matching lines
    /// are returned bare. For transfer entries the body is op-tagged
    /// (`"create <path>"` / `"update <path>"` / `"delete <path>"` /
    /// `"skip <path>"`).
    pub lines: Vec<String>,
    /// Total stdout lines in the recorded entry, before any filter. Zero
    /// for transfer entries.
    pub stdout_lines: u32,
    /// Total stderr lines in the recorded entry, before any filter. Zero
    /// for transfer entries.
    pub stderr_lines: u32,
    /// For transfer entries: the body length before the `op` filtered any
    /// lines out (channel concept does not apply). Omitted for `exec`
    /// entries because it would be a pure derivation of
    /// `stdout_lines` / `stderr_lines` and the `stream` selector — the
    /// caller can compute it without help.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_lines: Option<u32>,
    /// Set when the originating tool's body exceeded the per-entry byte cap
    /// and the buffer dropped the tail.
    pub truncated: bool,
}

/// Arguments to `get`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct GetParams {
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

/// Arguments to `put`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PutParams {
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

/// Arguments to `sync_get`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SyncGetParams {
    /// The host alias, as returned by `list_hosts`.
    pub host: String,
    /// The directory on the host to mirror down — absolute, or relative to
    /// the login directory, without a leading `~`. Must be an existing
    /// directory.
    pub remote_path: String,
    /// The local directory to mirror into — absolute, or starting with `~/`.
    /// Created if missing. Files inside this directory that are absent from
    /// the remote source are deleted.
    pub local_path: String,
    /// Optional glob patterns to skip, added to the host's configured
    /// exclude — a pattern matches a file or directory name anywhere in the
    /// tree, e.g. "target", ".git", "*.log".
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Arguments to `sync_put`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SyncPutParams {
    /// The host alias, as returned by `list_hosts`.
    pub host: String,
    /// The local directory to mirror up — absolute, or starting with `~/`.
    /// Must be an existing directory.
    pub local_path: String,
    /// The remote directory to mirror into — absolute, or relative to the
    /// login directory, without a leading `~`. Created if missing. Files
    /// inside this directory that are absent from the local source are
    /// deleted.
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
    /// Total bytes that crossed the wire, including tar framing, gzip
    /// overhead, and per-file metadata — not the sum of file content
    /// sizes. Useful as a rough transfer-cost indicator, not as a file-
    /// size measurement.
    pub bytes: u64,
}

/// The result of a `sync_get` / `sync_put` call: archive payload size plus
/// per-op counts derived from the change set. The full per-file list is
/// kept in the trace buffer; call `trace` to drill in.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SyncResult {
    /// Total bytes that crossed the wire (only files marked `created` or
    /// `updated` were sent), including tar framing, gzip overhead, and
    /// per-file metadata — not the sum of file content sizes. Zero when
    /// every file matched by sha-256.
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
        description = "**DO NOT pipe through `tail` / `head` / `grep` in the shell command — use the `op` pipeline instead.** Shell-side pipes scope before the daemon sees the bytes, so `trace` only has the post-pipe slice; double-scoping triggers an advisory `note` on the result.\n\nRun a shell command on a host from list_hosts. Returns the exit code, line counts, and (optionally) the scoped output. **Shell semantics depend on the remote OS**: POSIX hosts run the command under the user's login shell (bash/sh/zsh as configured); Windows hosts run it under whatever OpenSSH has set as the default shell (typically PowerShell or cmd.exe — `;` or `&&` for sequencing, `$env:VAR` under PowerShell, `%VAR%` under cmd.exe). Output bytes come back in the remote console code page (UTF-8 on POSIX, whatever `chcp` reports on Windows: e.g. 932 = Shift_JIS, 437 = OEM US) and are decoded on the daemon side, so callers always see UTF-8 strings. `op` is an ordered pipeline of steps — omit it or pass `[]` to get the metadata only (the full output stays in the per-session trace buffer for inspection through `trace`). To get the body inline, pass at least one step: `[{full: true}]` for everything, `[{tail: 50}]` for the last 50 lines, `[{grep: \"err\"}]` for matches, or chain — `[{head: 100}, {tail: 50}]` is a sliding window from line 51 to 100. Steps apply in order; the implicit start is the full body. Each call is stateless (no cwd or shell state carries over, use `cd /path && cmd`). Each call has a time limit (default 600s); for a longer-running job, start it detached and poll — e.g. \"nohup sh -c 'long-cmd; echo $? > /tmp/job.rc' > /tmp/job.out 2>&1 &\", then read /tmp/job.rc later."
    )]
    async fn exec(&self, params: Parameters<ExecParams>) -> Result<Json<ExecResult>, String> {
        let ExecParams { host, command, op } = params.0;
        validate_pipeline(&op)?;
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        let timeout = match config.host(&host) {
            Some(entry) => Duration::from_secs(config.exec_timeout_secs(entry)),
            None => return Err(format!("unknown host {host:?}")),
        };

        // The remote runs the command verbatim. The pool reads its
        // pooled connection's encoding (probed once at connect time)
        // and decodes the returned bytes accordingly, so the daemon
        // hands back UTF-8 strings regardless of whether the host is a
        // UTF-8 POSIX box or a CP932 Japanese Windows host.
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

        // The trace buffer holds the channel-tagged body in arrival order:
        // splitting the raw chunks gives the natural reading order of
        // progress lines and the warnings that landed between them, which
        // is what makes a long build log readable through `trace`.
        let trace_lines = chunks_to_lines(&output.chunks);
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
                lines: trace_lines,
                skipped: vec![],
                truncated: false,
            })
            .await;

        let (stdout, stdout_lines) = if op.is_empty() {
            // Body is omitted from the result; counts still come back so
            // the model can decide whether to drill into trace.
            (Vec::new(), stdout_all.len() as u32)
        } else {
            apply_pipeline(stdout_all, &op)?
        };
        let (stderr, stderr_lines) = if op.is_empty() {
            (Vec::new(), stderr_all.len() as u32)
        } else {
            apply_pipeline(stderr_all, &op)?
        };
        let note = detect_trailing_scope_pipe(&command).map(|program| {
            format!(
                "the command ends in `| {program}` — the shell scoped the output before the \
                 daemon saw it, so the trace buffer only holds what survived the pipe. Pass \
                 `op` (tail/head/grep) instead and let `trace` re-scope from the full stream."
            )
        });
        Ok(Json(ExecResult {
            exit_code: output.exit_code,
            stdout,
            stdout_lines,
            stderr,
            stderr_lines,
            note,
        }))
    }

    #[tool(
        name = "trace",
        description = "Re-inspect the full detail of a recent tool call on this MCP session. The other tools return slim summaries to keep context lean; trace retrieves the body that backed them. The `op` parameter is an ordered pipeline of steps — at least one step is required so the response stays deliberately scoped. Each step is one of `{full: true}`, `{head: N}`, `{tail: N}`, `{grep: STR}`; steps apply in order, with the implicit start being the full body. For example `[{full: true}]` returns everything, `[{tail: 50}]` the last 50, `[{grep: \"err\"}]` matching lines, and `[{head: 100}, {tail: 50}, {grep: \"x\"}]` reads the first 100, keeps the last 50 of those, then greps. `grep` matches the raw line text — never any `stdout:` / `stderr:` prefix — so a pattern that worked on the original `exec` result keeps working here. `stream` (default `both`) selects which channels of an `exec` entry to show: `both` prefixes each line with `stdout: ` or `stderr: ` and preserves the arrival order; `stdout` or `stderr` returns only that channel with no prefix. `stream` is ignored for transfer entries. `index` selects which past call to look at: 0 is the most recent (default), 1 the one before that, up to 4 — the buffer holds the last 5 calls per session. For transfer entries, set `include_skipped` to mix the hash-matched (skipped) paths into the body. trace itself is not recorded."
    )]
    async fn trace(&self, params: Parameters<TraceParams>) -> Result<Json<TraceResult>, String> {
        let TraceParams {
            index,
            op,
            stream,
            include_skipped,
        } = params.0;
        if op.is_empty() {
            return Err(
                "trace requires at least one op step — pass `[{full: true}]` for the whole body, \
                 or chain head/tail/grep to narrow"
                    .into(),
            );
        }
        validate_pipeline(&op)?;
        let entry = self
            .trace
            .fetch(index as usize)
            .await
            .ok_or_else(|| format!("no trace entry at index {index}"))?;

        // Raw per-channel counts of the recorded entry (before any filter).
        // These match the exec result's stdout_lines / stderr_lines so the
        // model has the same anchor whether it is reading the original
        // result or the trace.
        let stdout_lines_raw = entry
            .lines
            .iter()
            .filter(|l| l.channel == Channel::Stdout)
            .count() as u32;
        let stderr_lines_raw = entry
            .lines
            .iter()
            .filter(|l| l.channel == Channel::Stderr)
            .count() as u32;

        // Stream filter: keep lines whose channel matches the selector.
        // Transfer lines always pass through.
        let mut body: Vec<TraceLine> = entry
            .lines
            .iter()
            .filter(|l| l.channel.passes(stream))
            .cloned()
            .collect();
        // Skipped paths are channel-less; treat them as Transfer for output
        // formatting purposes (no prefix).
        if include_skipped {
            body.extend(entry.skipped.iter().map(|s| TraceLine {
                channel: Channel::Transfer,
                text: s.clone(),
            }));
        }
        // `total_lines` is meaningful for transfer entries — they have no
        // stdout/stderr split, so it's the only count the caller can read.
        // For `exec`, it would be a pure derivation of stdout_lines /
        // stderr_lines and the stream selector, so it is omitted.
        let is_transfer = body.iter().any(|l| l.channel == Channel::Transfer)
            || (stdout_lines_raw == 0 && stderr_lines_raw == 0);
        let total_lines = if is_transfer {
            Some(body.len() as u32)
        } else {
            None
        };

        let kept = apply_tagged_pipeline(body, &op)?;
        // Output formatting: prefix exec channels only when `stream = both`
        // (otherwise the prefix is unambiguous from the parameter the
        // caller already chose).
        let lines: Vec<String> = kept
            .into_iter()
            .map(|line| match (line.channel, stream) {
                (Channel::Stdout, Stream::Both) => format!("stdout: {}", line.text),
                (Channel::Stderr, Stream::Both) => format!("stderr: {}", line.text),
                _ => line.text,
            })
            .collect();

        Ok(Json(TraceResult {
            tool: entry.tool,
            params: entry.params,
            summary: entry.summary,
            lines,
            stdout_lines: stdout_lines_raw,
            stderr_lines: stderr_lines_raw,
            total_lines,
            truncated: entry.truncated,
        }))
    }

    #[tool(
        name = "get",
        description = "Download a file or directory from a host to the local machine. Files and directories are both supported (the tool name omits 'file' because the same call covers both). remote_path is on the host (absolute, or relative to the login directory — no leading ~); local_path is where it lands locally (absolute, or starting with ~/). If local_path is an existing directory the entry is placed inside it under its remote base name; otherwise local_path is replaced. The host's configured exclude patterns are always skipped; pass exclude to add more globs for this call. Result is a byte count only — the full per-file detail is not returned; call trace if you need it. `bytes` is the total transferred over the wire including tar framing and metadata, not the sum of file content sizes."
    )]
    async fn get(
        &self,
        params: Parameters<GetParams>,
    ) -> Result<Json<TransferResult>, String> {
        let GetParams {
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
        description = "Mirror a remote directory into a local location. Both paths are treated as roots — files on the local side that are absent from the remote source are deleted; files matching by sha256 are skipped. The remote source must be a directory; the local destination is created if missing. Returns per-op counts only (created/updated/deleted/skipped). **The per-file list is not in the result** — to see which files moved, call `trace` (the touched files come back as `<verb> <path>` lines; pass `include_skipped` to also see the hash-matched ones). The host's configured exclude patterns are always skipped; pass exclude to add more globs for this call. `bytes` is the total transferred over the wire (only created/updated files were sent), including tar framing and metadata — not the sum of file content sizes."
    )]
    async fn sync_get(
        &self,
        params: Parameters<SyncGetParams>,
    ) -> Result<Json<SyncResult>, String> {
        let SyncGetParams {
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
        description = "Mirror a local directory onto a host. Both paths are treated as roots — files on the remote that are absent from the local source are deleted; files matching by sha256 are skipped. The local source must be a directory; the remote destination is created if missing. Returns per-op counts only (created/updated/deleted/skipped). **The per-file list is not in the result** — to see which files moved, call `trace` (the touched files come back as `<verb> <path>` lines; pass `include_skipped` to also see the hash-matched ones). The inventory's configured exclude patterns are always skipped; pass exclude to add more globs for this call. `bytes` is the total transferred over the wire (only created/updated files were sent), including tar framing and metadata — not the sum of file content sizes."
    )]
    async fn sync_put(
        &self,
        params: Parameters<SyncPutParams>,
    ) -> Result<Json<SyncResult>, String> {
        let SyncPutParams {
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
        // Transfer lines have no stdout/stderr distinction; tag them as
        // Transfer so the stream selector in `trace` passes them through
        // unchanged regardless of which channel the caller asked for.
        let mut lines = Vec::new();
        let mut skipped = Vec::new();
        for entry in &sr.change_set.entries {
            let text = format!("{} {}", entry.op.verb(), entry.rel_path.display());
            if entry.op == crate::changeset::ChangeOp::Skip {
                skipped.push(text);
            } else {
                lines.push(TraceLine {
                    channel: Channel::Transfer,
                    text,
                });
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
        name = "put",
        description = "Upload a local file or directory to a host. Files and directories are both supported (the tool name omits 'file' because the same call covers both). local_path is the local source (absolute, or starting with ~/); remote_path is where it lands on the host (absolute, or relative to the login directory — no leading ~). If remote_path is an existing directory the entry is placed inside it under its local base name; otherwise remote_path is replaced. The inventory's configured exclude patterns (e.g. build output) are always skipped; pass exclude to add more globs for this call. Result is a byte count only — the full per-file detail is not returned; call trace if you need it. `bytes` is the total transferred over the wire including tar framing and metadata, not the sum of file content sizes."
    )]
    async fn put(
        &self,
        params: Parameters<PutParams>,
    ) -> Result<Json<TransferResult>, String> {
        let PutParams {
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

/// If the command's last unquoted pipe targets a line-scoping program,
/// return that program's name. The intent is to recognise the
/// "double-scoping" anti-pattern — piping through `tail` / `head` / `grep`
/// when the `op` parameter exists for exactly that purpose — and surface
/// an advisory `note` to the caller. Best-effort: a naive quote-aware scan
/// is enough to catch the common cases without growing a shell parser.
fn detect_trailing_scope_pipe(command: &str) -> Option<&'static str> {
    let bytes = command.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut last_pipe: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'\\' if !in_single && i + 1 < bytes.len() => {
                // Skip the escaped byte. (Inside single quotes `\` is
                // literal, so we only honour escapes outside single
                // quoting.)
                i += 2;
                continue;
            }
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'|' if !in_single && !in_double => {
                // `||` is logical-or, not a pipe — skip both bytes.
                if bytes.get(i + 1) == Some(&b'|') {
                    i += 2;
                    continue;
                }
                last_pipe = Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    let idx = last_pipe?;
    let after = &command[idx + 1..].trim_start();
    let first_word = after
        .split(|c: char| c.is_whitespace())
        .find(|w| !w.is_empty())?;
    match first_word {
        "tail" => Some("tail"),
        "head" => Some("head"),
        "grep" => Some("grep"),
        "egrep" => Some("egrep"),
        "fgrep" => Some("fgrep"),
        "rg" => Some("rg"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_trailing_tail_pipe() {
        assert_eq!(
            detect_trailing_scope_pipe("ls -la | tail -5"),
            Some("tail")
        );
    }

    #[test]
    fn detects_a_trailing_grep_after_an_unrelated_pipe() {
        // The model used awk to extract, then grep to scope — the *last*
        // pipe is the one that mattered for the advisory.
        assert_eq!(
            detect_trailing_scope_pipe("ls | awk '{print $1}' | grep foo"),
            Some("grep")
        );
    }

    #[test]
    fn ignores_a_pipe_inside_quotes() {
        // The `|` lives inside single quotes — not a real pipe operator.
        assert!(detect_trailing_scope_pipe("echo 'a | tail'").is_none());
        assert!(detect_trailing_scope_pipe(r#"echo "a | grep b""#).is_none());
    }

    #[test]
    fn ignores_logical_or() {
        // `||` is logical-or, not a pipe.
        assert!(detect_trailing_scope_pipe("cmd1 || cmd2").is_none());
    }

    #[test]
    fn ignores_unrelated_trailing_pipe_targets() {
        // `wc` and `sort` aren't on the scoping list; the model using them
        // is doing something different, not double-scoping.
        assert!(detect_trailing_scope_pipe("ls | wc -l").is_none());
        assert!(detect_trailing_scope_pipe("ls | sort").is_none());
    }

    #[test]
    fn detects_through_a_redirect_block_correctly() {
        // The `2>&1` is not a pipe; the last real pipe still targets head.
        assert_eq!(
            detect_trailing_scope_pipe("cmd 2>&1 | head -3"),
            Some("head")
        );
    }

    #[test]
    fn returns_none_when_there_is_no_pipe() {
        assert!(detect_trailing_scope_pipe("ls -la").is_none());
        assert!(detect_trailing_scope_pipe("echo hi; echo bye").is_none());
    }
}
