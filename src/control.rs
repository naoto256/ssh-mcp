//! The policy control handler and the `hook`-gate sub-process runner.
//!
//! The hook proxy forwards a PreToolUse request over the control socket; the
//! daemon evaluates the host's policy — running any `hook` gate as a
//! sub-process — and returns the decision the proxy relays back to the
//! harness. Every abnormal path fails closed.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use std::time::Duration;

use crate::audit::AuditLog;
use crate::changeset;
use crate::config::HostsConfig;
use crate::pathnorm::{normalize_local, normalize_remote};
use crate::policy::{Decision, Evaluator, Subject, Tool, combine_gates};
use crate::ssh::ConnectionPool;

/// The PreToolUse request the hook forwards: the tool name and its input, plus
/// the session's permission mode, which sets the no-match fallback.
#[derive(Deserialize)]
struct PreToolUseRequest {
    #[serde(default, alias = "permissionMode")]
    permission_mode: Option<String>,
    #[serde(default, alias = "toolName")]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: ToolInput,
}

#[derive(Deserialize, Default)]
struct ToolInput {
    host: Option<String>,
    /// Present for `exec`.
    command: Option<String>,
    /// Present for `get_file` / `put_file` / `sync_get` / `sync_put`.
    remote_path: Option<String>,
    local_path: Option<String>,
    /// Per-call exclude additions for transfers. Optional and additive on
    /// top of the inventory's configured excludes.
    #[serde(default)]
    exclude: Vec<String>,
}

/// The direction of a file transfer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TransferDir {
    Get,
    Put,
}

/// Shape of the transfer for gating purposes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TransferKind {
    /// `get_file` / `put_file`: single source path, cp-merge target, one
    /// `(remote_path, local_path)` pair to gate.
    Single,
    /// `sync_get` / `sync_put`: directory mirror, per-entry gating against
    /// the change set built from `find -print0` on both sides.
    Sync,
}

/// A file transfer request, as the control handler sees it.
struct Transfer<'a> {
    direction: TransferDir,
    kind: TransferKind,
    remote_path: &'a str,
    local_path: &'a str,
    exclude: &'a [String],
}

/// Handle one control-socket connection. This never panics and always writes a
/// decision: any failure is reported to stderr and answered with `deny`.
pub async fn handle_connection(
    mut stream: UnixStream,
    config_path: &Path,
    evaluator: &Evaluator,
    pool: &ConnectionPool,
    audit: &AuditLog,
) {
    let (decision, reason) = match process(&mut stream, config_path, evaluator, pool, audit).await {
        Ok((host, decision)) => (decision, format!("ssh-mcp policy for host {host:?}")),
        Err(e) => {
            eprintln!("ssh-mcp: control request failed, denying: {e:#}");
            (
                Decision::Deny,
                format!("ssh-mcp could not evaluate the request: {e:#}"),
            )
        }
    };
    let response = hook_output(decision, &reason);
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Read a request, evaluate it, record it, and return the host and decision.
async fn process(
    stream: &mut UnixStream,
    config_path: &Path,
    evaluator: &Evaluator,
    pool: &ConnectionPool,
    audit: &AuditLog,
) -> Result<(String, Decision)> {
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .await
        .context("reading the control request")?;

    let request: PreToolUseRequest =
        serde_json::from_str(&raw).context("parsing the PreToolUse request")?;
    let mode = request
        .permission_mode
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let fallback = fallback_for_mode(&mode);
    let host = request
        .tool_input
        .host
        .clone()
        .context("the request carries no host")?;

    let config = HostsConfig::load(config_path).context("loading the host inventory")?;

    let tool = request.tool_name.as_deref().unwrap_or_default();
    let (decision, summary) = match tool {
        "mcp__ssh__get" | "mcp__ssh__put" | "mcp__ssh__sync_get" | "mcp__ssh__sync_put" => {
            let remote = request
                .tool_input
                .remote_path
                .clone()
                .context("the transfer request carries no remote_path")?;
            let local = request
                .tool_input
                .local_path
                .clone()
                .context("the transfer request carries no local_path")?;
            let exclude = request.tool_input.exclude.clone();
            let direction = if matches!(tool, "mcp__ssh__get" | "mcp__ssh__sync_get") {
                TransferDir::Get
            } else {
                TransferDir::Put
            };
            let kind = if matches!(tool, "mcp__ssh__sync_get" | "mcp__ssh__sync_put") {
                TransferKind::Sync
            } else {
                TransferKind::Single
            };
            let transfer = Transfer {
                direction,
                kind,
                remote_path: &remote,
                local_path: &local,
                exclude: &exclude,
            };
            let decision =
                decide_transfer(evaluator, &config, pool, &host, &transfer, &raw, fallback).await;
            (decision, format!("{tool} {remote} <-> {local}"))
        }
        _ => {
            let command = request
                .tool_input
                .command
                .clone()
                .context("the request carries no command")?;
            let decision = decide_subject(
                evaluator,
                &config,
                &host,
                Subject::Command(&command),
                &raw,
                fallback,
            )
            .await;
            (decision, command)
        }
    };

    audit.record_decision(&host, &summary, &mode, decision_label(decision));
    Ok((host, decision))
}

/// The no-match fallback for a permission mode. Claude Code's `default` mode
/// prompts on an unmatched tool; `bypassPermissions` auto-approves it. Any
/// other mode, or an absent value, prompts — the safe default.
fn fallback_for_mode(mode: &str) -> Decision {
    match mode {
        "bypassPermissions" => Decision::Allow,
        _ => Decision::Ask,
    }
}

/// The audit-log label for a decision. Distinct from [`hook_output`]'s wire
/// mapping, which folds the impossible `Unset` into `deny`; the log records
/// the decision as-is.
fn decision_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
        Decision::Unset => "unset",
    }
}

/// Compose a host's full policy decision for one subject: the rule-based gates
/// plus every `hook` gate, combined strictest-wins. `fallback` is the no-match
/// outcome for the request's permission mode.
async fn decide_subject(
    evaluator: &Evaluator,
    config: &HostsConfig,
    host: &str,
    subject: Subject<'_>,
    raw_request: &str,
    fallback: Decision,
) -> Decision {
    let Some(host_entry) = config.host(host) else {
        // The model only learns of hosts through `list_hosts`.
        return Decision::Deny;
    };
    // An empty gate set is equivalent to `free`.
    if host_entry.policy.is_empty() {
        return Decision::Allow;
    }

    let rule_gates = match evaluator.evaluate_rule_gates(config, host_entry, &subject) {
        Ok(gates) => gates,
        Err(e) => {
            eprintln!("ssh-mcp: rule evaluation failed, denying: {e:#}");
            return Decision::Deny;
        }
    };

    let mut decisions = rule_gates.decisions;
    for program in &rule_gates.hook_programs {
        decisions.push(run_subhook(program, raw_request).await);
    }
    combine_gates(&decisions, fallback)
}

/// Decide a file transfer. A transfer has two independent sides: the remote
/// path, gated by the host's own policy, and the local path, gated by the
/// user's Claude Code settings regardless of the host. Both are resolved to a
/// concrete decision and the stricter one wins — so a `free` host can never
/// let a transfer touch a local path the user's own rules protect.
async fn decide_transfer(
    evaluator: &Evaluator,
    config: &HostsConfig,
    pool: &ConnectionPool,
    host: &str,
    transfer: &Transfer<'_>,
    raw_request: &str,
    fallback: Decision,
) -> Decision {
    // A path that will not normalize is treated as hostile and denied. Both
    // sides are normalized here, exactly as the transfer itself normalizes
    // them, so the gate and the transfer can never disagree on a `..`.
    let remote = match normalize_remote(transfer.remote_path) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("ssh-mcp: rejecting a transfer with a bad remote path: {e:#}");
            return Decision::Deny;
        }
    };
    let local_buf = match normalize_local(transfer.local_path) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("ssh-mcp: rejecting a transfer with a bad local path: {e:#}");
            return Decision::Deny;
        }
    };
    let local = local_buf.to_string_lossy();

    // A download reads the remote and writes the local; an upload, the reverse.
    let (remote_tool, local_tool) = match transfer.direction {
        TransferDir::Get => (Tool::Read, Tool::Write),
        TransferDir::Put => (Tool::Write, Tool::Read),
    };

    if transfer.kind == TransferKind::Sync {
        return decide_sync(
            evaluator,
            config,
            pool,
            host,
            transfer,
            &remote,
            &local_buf,
            remote_tool,
            local_tool,
            raw_request,
            fallback,
        )
        .await;
    }

    let remote_decision = decide_subject(
        evaluator,
        config,
        host,
        Subject::Path {
            tool: remote_tool,
            path: &remote,
        },
        raw_request,
        fallback,
    )
    .await;

    let local_decision = match evaluator.check_user_path(local_tool, &local) {
        Ok(decision) => combine_gates(&[decision], fallback),
        Err(e) => {
            eprintln!("ssh-mcp: local policy check failed, denying: {e:#}");
            return Decision::Deny;
        }
    };

    combine_gates(&[remote_decision, local_decision], fallback)
}

/// Per-entry policy evaluation for `sync_get` / `sync_put`. The hook walks
/// both sides with `find -print0` (no hashing — `Skip` vs `Update` is not a
/// policy distinction), classifies every path that would be touched, and
/// gates each one against the host's policy on the remote side and the
/// user's settings on the local side. The single decision returned to the
/// harness is strictest-wins across all entries; one `Deny` ruins the
/// transfer, one `Ask` surfaces a prompt covering the whole change set.
#[allow(clippy::too_many_arguments)]
async fn decide_sync(
    evaluator: &Evaluator,
    config: &HostsConfig,
    pool: &ConnectionPool,
    host: &str,
    transfer: &Transfer<'_>,
    remote: &str,
    local: &Path,
    remote_tool: Tool,
    local_tool: Tool,
    raw_request: &str,
    fallback: Decision,
) -> Decision {
    // The path walks consume the host's exec budget. A walk takes far less
    // than a normal exec — `find -print0` only — but bounding it on the
    // same dial keeps configuration in one place.
    let host_entry = match config.host(host) {
        Some(entry) => entry,
        None => return Decision::Deny,
    };
    let timeout = Duration::from_secs(config.exec_timeout_secs(host_entry));

    // sync_* leaves both paths as roots — no cp-merge — so the per-entry
    // remote and local absolute paths are simply `root + rel`.
    let empty = PathBuf::new();
    let local_excludes = match changeset::compile_excludes(transfer.exclude) {
        Ok(set) => set,
        Err(e) => {
            eprintln!("ssh-mcp: invalid exclude in sync request: {e:#}");
            return Decision::Deny;
        }
    };
    let (name_only, _complex) = changeset::partition_excludes(transfer.exclude);

    let (source_root_remote, source_is_remote) = match transfer.direction {
        TransferDir::Get => (Some(remote), true),
        TransferDir::Put => (None, false),
    };

    // Local path walk.
    let local_paths = match changeset::walk_local_paths(local, &empty, &local_excludes) {
        Ok(set) => set,
        Err(e) => {
            eprintln!("ssh-mcp: local walk failed in sync gate: {e:#}");
            return Decision::Deny;
        }
    };

    // Remote path walk via a one-shot exec on the daemon's pool. The
    // command no-ops cleanly when the remote root does not exist yet, so a
    // first-run sync just sees an empty remote set. The shell command
    // depends on the remote OS, so we read it off the cached probe and
    // branch.
    let remote_os = match pool.remote_os(config, host).await {
        Ok(os) => os,
        Err(e) => {
            eprintln!("ssh-mcp: cannot determine remote OS for sync gate: {e:#}");
            return Decision::Deny;
        }
    };
    let remote_walk_cmd = match remote_os {
        crate::ssh::RemoteOs::Posix => {
            changeset::remote_paths_walk_command_safe(remote, &name_only)
        }
        crate::ssh::RemoteOs::Windows => {
            changeset::remote_paths_walk_command_safe_windows(remote, &name_only)
        }
    };
    let remote_walk_out = match pool.exec(config, host, &remote_walk_cmd, timeout).await {
        Ok(out) if out.exit_code == 0 => out.stdout,
        Ok(out) => {
            eprintln!(
                "ssh-mcp: remote walk in sync gate exited {}: {}",
                out.exit_code,
                out.stderr.trim()
            );
            return Decision::Deny;
        }
        Err(e) => {
            eprintln!("ssh-mcp: remote walk in sync gate failed: {e:#}");
            return Decision::Deny;
        }
    };
    let remote_paths = match remote_os {
        crate::ssh::RemoteOs::Posix => changeset::parse_paths_walk_output(&remote_walk_out, &empty),
        crate::ssh::RemoteOs::Windows => {
            changeset::parse_paths_walk_output_lines(&remote_walk_out, &empty)
        }
    };

    // The source side is the one we copy *from*; the dest side is where
    // deletes can come from. compute_paths is direction-aware via which
    // set we hand it.
    let (source_set, dest_set) = if source_is_remote {
        (&remote_paths, &local_paths)
    } else {
        (&local_paths, &remote_paths)
    };
    let entries = changeset::compute_paths(source_set, dest_set, /* mirror = */ true);
    let _ = source_root_remote; // direction is encoded in the (source, dest) pairing above

    if entries.is_empty() {
        // Nothing would change; nothing to ask about. Allow trivially.
        return Decision::Allow;
    }

    let mut decisions: Vec<Decision> = Vec::with_capacity(entries.len() * 2);
    for entry in &entries {
        let rel = entry.rel_path.to_string_lossy();
        let remote_abs = join_remote(remote, &rel);
        let local_abs = local.join(&entry.rel_path);
        let local_abs_display = local_abs.to_string_lossy();

        let remote_d = decide_subject(
            evaluator,
            config,
            host,
            Subject::Path {
                tool: remote_tool,
                path: &remote_abs,
            },
            raw_request,
            fallback,
        )
        .await;
        let local_d = match evaluator.check_user_path(local_tool, &local_abs_display) {
            Ok(d) => combine_gates(&[d], fallback),
            Err(e) => {
                eprintln!("ssh-mcp: local policy check failed in sync gate: {e:#}");
                return Decision::Deny;
            }
        };
        decisions.push(remote_d);
        decisions.push(local_d);
        if matches!(remote_d, Decision::Deny) || matches!(local_d, Decision::Deny) {
            // One deny is enough; short-circuit to avoid hammering hook
            // sub-processes once the answer is known.
            return Decision::Deny;
        }
    }
    combine_gates(&decisions, fallback)
}

/// Join a normalized remote root with a relative path. The result keeps
/// the root's leading `/` and uses `/` as the separator regardless of how
/// the local `PathBuf` would have printed.
fn join_remote(root: &str, rel: &str) -> String {
    if rel.is_empty() {
        return root.to_string();
    }
    let trimmed = root.trim_end_matches('/');
    format!("{trimmed}/{rel}")
}

/// Run one `hook` gate. A gate that cannot be evaluated fails closed.
async fn run_subhook(program: &str, raw_request: &str) -> Decision {
    match spawn_subhook(program, raw_request).await {
        Ok(decision) => decision,
        Err(e) => {
            eprintln!("ssh-mcp: hook gate {program:?} failed, denying: {e:#}");
            Decision::Deny
        }
    }
}

async fn spawn_subhook(program: &str, raw_request: &str) -> Result<Decision> {
    let path = expand_tilde(program);
    let mut child = tokio::process::Command::new(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning hook gate {}", path.display()))?;

    {
        let mut stdin = child.stdin.take().context("the hook gate has no stdin")?;
        stdin
            .write_all(raw_request.as_bytes())
            .await
            .context("writing to the hook gate")?;
        // `stdin` is dropped here, signalling end-of-input to the child.
    }

    let output = child
        .wait_with_output()
        .await
        .context("waiting for the hook gate")?;

    // Claude Code hook protocol: exit code 2 blocks the tool call.
    if output.status.code() == Some(2) {
        return Ok(Decision::Deny);
    }
    parse_hook_decision(&output.stdout)
}

/// Parse a sub-hook's `hookSpecificOutput` into a decision. No output means
/// the hook is non-blocking — it abstains.
fn parse_hook_decision(stdout: &[u8]) -> Result<Decision> {
    let text = std::str::from_utf8(stdout)
        .context("the hook gate output is not UTF-8")?
        .trim();
    if text.is_empty() {
        return Ok(Decision::Unset);
    }
    let value: serde_json::Value =
        serde_json::from_str(text).context("the hook gate output is not JSON")?;
    let decision = value
        .get("hookSpecificOutput")
        .and_then(|output| output.get("permissionDecision"))
        .and_then(|decision| decision.as_str());
    Ok(match decision {
        Some("allow") => Decision::Allow,
        Some("deny") => Decision::Deny,
        Some("ask") => Decision::Ask,
        // `defer` or an absent decision is an abstention.
        Some("defer") | None => Decision::Unset,
        Some(other) => anyhow::bail!("the hook gate returned an unknown decision {other:?}"),
    })
}

/// Build the `hookSpecificOutput` JSON the harness expects from a hook.
fn hook_output(decision: Decision, reason: &str) -> String {
    let permission = match decision {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        // `Unset` cannot reach here, but fail closed if it ever does.
        Decision::Deny | Decision::Unset => "deny",
    };
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    })
    .to_string()
}

/// Expand a leading `~/` against `$HOME`.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_hook_decision() {
        let make = |d: &str| format!(r#"{{"hookSpecificOutput":{{"permissionDecision":"{d}"}}}}"#);
        assert_eq!(
            parse_hook_decision(make("allow").as_bytes()).unwrap(),
            Decision::Allow
        );
        assert_eq!(
            parse_hook_decision(make("deny").as_bytes()).unwrap(),
            Decision::Deny
        );
        assert_eq!(
            parse_hook_decision(make("ask").as_bytes()).unwrap(),
            Decision::Ask
        );
    }

    #[test]
    fn empty_hook_output_abstains() {
        assert_eq!(parse_hook_decision(b"").unwrap(), Decision::Unset);
        assert_eq!(parse_hook_decision(b"   \n").unwrap(), Decision::Unset);
    }

    #[test]
    fn invalid_hook_output_is_an_error() {
        assert!(parse_hook_decision(b"not json").is_err());
    }

    #[test]
    fn hook_output_maps_decisions_to_permission_strings() {
        assert!(hook_output(Decision::Allow, "r").contains(r#""permissionDecision":"allow""#));
        assert!(hook_output(Decision::Ask, "r").contains(r#""permissionDecision":"ask""#));
        assert!(hook_output(Decision::Deny, "r").contains(r#""permissionDecision":"deny""#));
    }
}
