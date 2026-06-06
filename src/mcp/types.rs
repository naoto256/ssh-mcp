//! Param and result types for every MCP tool. Kept in one file so the
//! schema surface of the server is readable end-to-end without chasing
//! the handler modules. Each struct derives `Serialize` + `Deserialize` +
//! `JsonSchema` because rmcp turns these into the wire JSON for tool
//! input/output validation.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::trace::{OpStep, Stream};

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

/// One public identity held by the user's SSH agent, as surfaced by
/// `list_agent_keys`. Mirrors what `ssh-add -L` would print — public bytes
/// only, no private key material.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AgentKey {
    /// The OpenSSH algorithm name, e.g. `"ssh-ed25519"`, `"ssh-rsa"`,
    /// `"ecdsa-sha2-nistp256"`.
    // `type` is a reserved word; `r#type` lets us keep the wire name
    // unchanged (serde uses the raw identifier without the `r#`).
    pub r#type: String,
    /// The comment attached to the agent identity, often `user@host`. May
    /// be empty.
    pub comment: String,
    /// SHA-256 fingerprint in the canonical OpenSSH form
    /// (`"SHA256:..."`).
    pub fingerprint: String,
    /// The full OpenSSH single-line public key — paste this into a host's
    /// `~/.ssh/authorized_keys` to let the agent's holder sign in.
    pub public_key: String,
}

/// The `list_agent_keys` result. Wrapped in an object because MCP requires
/// object roots, and so an empty agent surfaces as `{"keys": []}` rather
/// than a bare `[]`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AgentKeyList {
    pub keys: Vec<AgentKey>,
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
    /// body inline, pass at least one step: `[{"full": true}]` for
    /// everything, `[{"tail": 50}]` for the last 50, `[{"grep": "err"}]`
    /// for matching lines, or chain — `[{"head": 100}, {"tail": 50},
    /// {"grep": "x"}]` reads the first 100, then keeps the last 50 of
    /// those (a sliding window from line 51 to 100), then greps. The
    /// implicit starting point is the full body, so `{"full": true}` only
    /// needs to be written when it's the lone step.
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
    /// Advisory note from the daemon. Emitted when inline output exceeds the
    /// response byte cap and the full body is available through `trace`, or
    /// when the command's last unquoted pipe targets a line-scoping program
    /// (`tail`, `head`, `grep`, `egrep`, `fgrep`, `rg`) — the shell will have
    /// already dropped everything past that pipe, so the trace buffer only
    /// holds the post-pipe slice. Pass the scope through `op` instead and let
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
    /// Each step is one of `{"full": true}`, `{"head": N}`, `{"tail": N}`,
    /// or `{"grep": "STR"}`; chain them to compose. `grep` matches the raw line
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

/// Arguments to `propose_host`.
///
/// The shape mirrors the on-disk `[hosts.<alias>]` table for the fields the
/// model is allowed to set. `alias`, `policy`, and `disabled` are not in
/// here — the server picks the alias, hard-codes the policy to `["claude"]`,
/// and always writes `disabled = true` so the entry is inactive until the
/// user edits the TOML by hand.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ProposeHostParams {
    /// The host's address — IP literal or DNS name.
    pub hostname: String,
    /// The login user.
    pub user: String,
    /// Short human-readable description of what the host is for. Shown in
    /// `list_hosts` once the entry is activated.
    pub purpose: String,
    /// Auto-expiry time as an RFC 3339 datetime, e.g.
    /// `"2026-05-27T19:30:00+09:00"`. Must be in the future and no more
    /// than 30 days out — the daemon removes the entry from the TOML on the
    /// next load after this passes.
    pub expires_at: String,
    /// SSH port. Defaults to 22.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Optional free-form tags carried into the entry's `tags` array.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Aliases of jump hosts to chain through, nearest hop first. Each must
    /// exist as an active (non-disabled, non-expired) host in the inventory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_jump: Vec<String>,
    /// Pinned host public key in OpenSSH single-line format
    /// (e.g. `"ssh-ed25519 AAAA... comment"`). The daemon verifies the live
    /// server key against this value on connect instead of consulting
    /// `~/.ssh/known_hosts`. Required so every `propose_host` entry is
    /// self-contained — harvest it out-of-band from the cloud provider's
    /// console or by running `ssh-keyscan` via `exec` before calling this
    /// tool.
    pub host_key: String,
}

/// The result of `propose_host`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ProposeHostResult {
    /// Always `"proposed"` on success. Surfaces only as a sanity flag for
    /// the caller — the real signal is that the call returned at all.
    pub status: String,
    /// The alias the server assigned (e.g. `"tmp-a3f2k9"`). Will become
    /// addressable from `exec` once the user removes `disabled = true`.
    pub alias: String,
    /// Absolute path of the ephemeral TOML file the entry was appended to.
    /// Tell the user to open this and flip `disabled`.
    pub config_path: String,
    /// The exact block that was appended, including the activation comment.
    /// Lets the model echo it back to the user verbatim.
    pub snippet: String,
    /// Short imperative sentence describing how to activate the entry.
    pub activate_hint: String,
    /// Echo of the validated `expires_at` (RFC 3339).
    pub expires_at: String,
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
