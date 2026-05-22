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

use crate::audit::AuditLog;
use crate::config::HostsConfig;
use crate::policy::{Decision, Evaluator, combine_gates};

/// The PreToolUse request the hook forwards: the tool input, plus the session's
/// permission mode, which sets the no-match fallback.
#[derive(Deserialize)]
struct PreToolUseRequest {
    #[serde(default, alias = "permissionMode")]
    permission_mode: Option<String>,
    #[serde(default)]
    tool_input: ToolInput,
}

#[derive(Deserialize, Default)]
struct ToolInput {
    host: Option<String>,
    command: Option<String>,
}

/// Handle one control-socket connection. This never panics and always writes a
/// decision: any failure is reported to stderr and answered with `deny`.
pub async fn handle_connection(
    mut stream: UnixStream,
    config_path: &Path,
    evaluator: &Evaluator,
    audit: &AuditLog,
) {
    let (decision, reason) = match process(&mut stream, config_path, evaluator, audit).await {
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
    let host = request
        .tool_input
        .host
        .context("the request carries no host")?;
    let command = request
        .tool_input
        .command
        .context("the request carries no command")?;

    let config = HostsConfig::load(config_path).context("loading the host inventory")?;
    let decision = decide(
        evaluator,
        &config,
        &host,
        &command,
        &raw,
        fallback_for_mode(&mode),
    )
    .await;

    audit.record_decision(&host, &command, &mode, decision_label(decision));
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

/// Compose a host's full policy decision: the rule-based gates plus every
/// `hook` gate, combined strictest-wins. `fallback` is the no-match outcome
/// for the request's permission mode.
async fn decide(
    evaluator: &Evaluator,
    config: &HostsConfig,
    host: &str,
    command: &str,
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

    let rule_gates = match evaluator.evaluate_rule_gates(host_entry, command) {
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
