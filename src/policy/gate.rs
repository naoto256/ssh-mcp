//! Gate evaluation: composing a host's `policy` array into one decision.
//!
//! Each gate produces a decision; the host's decision is the strictest of
//! them (`deny` > `ask` > `allow`). A gate may also abstain (`Unset`); if
//! every gate abstains the host fails closed to `Deny`.

use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::Decision;
use super::permission::{PermissionSet, Tool};
use crate::config::{Gate, HostEntry, HostsConfig, NamedGate, Permissions};

/// The subset of `~/.claude/settings.json` the `claude` gate needs.
#[derive(Debug, Default, Deserialize)]
struct ClaudeSettings {
    #[serde(default)]
    permissions: Permissions,
}

/// What a host policy is being evaluated against: a shell command, as `exec`
/// runs it, or a file path accessed with a tool, as a transfer does.
pub enum Subject<'a> {
    Command(&'a str),
    Path { tool: Tool, path: &'a str },
}

impl Subject<'_> {
    /// Apply a rule set to this subject, in the form each one expects.
    fn evaluate(&self, set: &PermissionSet) -> Decision {
        match self {
            Subject::Command(command) => set.evaluate_command(command),
            Subject::Path { tool, path } => set.check(*tool, path),
        }
    }
}

/// Evaluates host policies. Holds the path to the user's Claude Code settings
/// so the `claude` gate can be redirected in tests.
pub struct Evaluator {
    claude_settings_path: PathBuf,
}

impl Evaluator {
    /// An evaluator reading the real `~/.claude/settings.json`.
    pub fn new() -> Result<Self> {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        Ok(Self {
            claude_settings_path: PathBuf::from(home).join(".claude").join("settings.json"),
        })
    }

    /// An evaluator whose `claude` gate reads `path` instead of the real file.
    pub fn with_claude_settings_path(path: PathBuf) -> Self {
        Self {
            claude_settings_path: path,
        }
    }

    /// Evaluate a command against a host's policy, treating every `hook` gate
    /// as abstaining. This is the offline path; the live server additionally
    /// runs the hook gates returned by [`evaluate_rule_gates`].
    ///
    /// When no gate has an opinion the result is `Ask` — the fallback of
    /// Claude Code's `default` permission mode. The live server picks the
    /// fallback from the request's actual mode.
    ///
    /// A host that is not in the config is denied: the model only learns of
    /// hosts through `list_hosts`, so an unknown alias is treated as hostile.
    pub fn evaluate(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        command: &str,
    ) -> Result<Decision> {
        let Some(host) = config.host(host_alias) else {
            return Ok(Decision::Deny);
        };
        // An empty gate set is equivalent to `free`.
        if host.policy.is_empty() {
            return Ok(Decision::Allow);
        }
        let rules = self.evaluate_rule_gates(host, &Subject::Command(command))?;
        let mut decisions = rules.decisions;
        decisions.extend(rules.hook_programs.iter().map(|_| Decision::Unset));
        Ok(combine_gates(&decisions, Decision::Ask))
    }

    /// Check a local path against the user's Claude Code settings alone.
    ///
    /// This gates the local side of a file transfer, independent of the host's
    /// own policy: a `free` host means the remote may be used freely, never
    /// that a transfer may read or write a local path the user's own rules
    /// protect.
    pub fn check_user_path(&self, tool: Tool, path: &str) -> Result<Decision> {
        let set = PermissionSet::from_permissions(&self.load_claude_permissions()?)?;
        Ok(set.check(tool, path))
    }

    /// Evaluate the rule-based gates (`free`, `def`, `claude`) of a non-empty
    /// host policy. Hook gates are not run here — they require spawning a
    /// subprocess — so their program paths are returned for the caller.
    ///
    /// The caller handles the empty-policy and unknown-host cases, runs the
    /// returned hook programs, and applies [`combine_gates`] to the full set.
    pub fn evaluate_rule_gates(&self, host: &HostEntry, subject: &Subject) -> Result<RuleGates> {
        // The `def` and `claude` gates share the Claude Code rule grammar, so
        // their rules are merged into one set and evaluated once.
        let mut merged = Permissions::default();
        let mut has_rule_gate = false;
        let mut decisions: Vec<Decision> = Vec::new();
        let mut hook_programs: Vec<String> = Vec::new();

        for gate in &host.policy {
            match gate {
                Gate::Named(NamedGate::Free) => decisions.push(Decision::Allow),
                Gate::Named(NamedGate::Def) => {
                    if let Some(rules) = host.def.as_ref() {
                        merged.merge_from(rules);
                    }
                    has_rule_gate = true;
                }
                Gate::Named(NamedGate::Claude) => {
                    merged.merge_from(&self.load_claude_permissions()?);
                    has_rule_gate = true;
                }
                Gate::Hook { hook } => hook_programs.push(hook.clone()),
            }
        }

        if has_rule_gate {
            let set = PermissionSet::from_permissions(&merged)?;
            decisions.push(subject.evaluate(&set));
        }

        Ok(RuleGates {
            decisions,
            hook_programs,
        })
    }

    fn load_claude_permissions(&self) -> Result<Permissions> {
        match std::fs::read_to_string(&self.claude_settings_path) {
            Ok(text) => {
                let settings: ClaudeSettings = serde_json::from_str(&text).with_context(|| {
                    format!("failed to parse {}", self.claude_settings_path.display())
                })?;
                Ok(settings.permissions)
            }
            // A missing settings file simply contributes no rules.
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Permissions::default()),
            Err(e) => Err(e)
                .with_context(|| format!("failed to read {}", self.claude_settings_path.display())),
        }
    }
}

/// The outcome of evaluating a host's rule-based gates: one decision per
/// `free`/`def`/`claude` gate, plus the program path of each `hook` gate
/// that still needs to be run.
pub struct RuleGates {
    pub decisions: Vec<Decision>,
    pub hook_programs: Vec<String>,
}

/// Combine gate decisions: the strictest opinion wins, abstentions are
/// ignored, and a policy where every gate abstains resolves to `fallback`.
///
/// `fallback` is the no-match outcome of the caller's permission mode — `Ask`
/// for `default` mode, `Allow` for `bypassPermissions`. A genuine error path
/// (an unreachable daemon, a failed evaluation) is denied by the caller before
/// reaching here, not folded into this fallback.
pub fn combine_gates(decisions: &[Decision], fallback: Decision) -> Decision {
    let rank = |d: Decision| match d {
        Decision::Deny => 2,
        Decision::Ask => 1,
        Decision::Allow => 0,
        Decision::Unset => unreachable!("abstentions are filtered before ranking"),
    };
    decisions
        .iter()
        .copied()
        .filter(|d| *d != Decision::Unset)
        .max_by_key(|d| rank(*d))
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> HostsConfig {
        HostsConfig::parse(toml).expect("test config should parse")
    }

    /// An evaluator whose `claude` gate finds no settings file.
    fn evaluator() -> Evaluator {
        Evaluator::with_claude_settings_path(PathBuf::from("/nonexistent/settings.json"))
    }

    #[test]
    fn free_host_allows_anything() {
        let cfg = config(
            r#"
            [hosts.lab]
            hostname = "h"
            purpose  = "p"
            policy   = ["free"]
        "#,
        );
        assert_eq!(
            evaluator().evaluate(&cfg, "lab", "rm -rf /").unwrap(),
            Decision::Allow
        );
    }

    #[test]
    fn unknown_host_is_denied() {
        let cfg = config("");
        assert_eq!(
            evaluator().evaluate(&cfg, "ghost", "ls").unwrap(),
            Decision::Deny
        );
    }

    #[test]
    fn def_gate_applies_inline_rules() {
        let cfg = config(
            r#"
            [hosts.staging]
            hostname = "h"
            purpose  = "p"
            policy   = ["def"]
            [hosts.staging.def]
            allow = ["Bash(systemctl status:*)"]
            deny  = ["Bash(rm:*)"]
        "#,
        );
        let ev = evaluator();
        assert_eq!(
            ev.evaluate(&cfg, "staging", "systemctl status nginx")
                .unwrap(),
            Decision::Allow
        );
        assert_eq!(
            ev.evaluate(&cfg, "staging", "rm -rf /var").unwrap(),
            Decision::Deny
        );
    }

    #[test]
    fn def_gate_with_no_matching_rule_falls_back_to_ask() {
        let cfg = config(
            r#"
            [hosts.staging]
            hostname = "h"
            purpose  = "p"
            policy   = ["def"]
            [hosts.staging.def]
            allow = ["Bash(ls:*)"]
        "#,
        );
        // No rule matches `whoami`; the offline path uses the default-mode
        // fallback, `Ask`.
        assert_eq!(
            evaluator().evaluate(&cfg, "staging", "whoami").unwrap(),
            Decision::Ask
        );
    }

    #[test]
    fn strictest_gate_wins() {
        // `free` allows, `def` denies — the deny must win.
        let cfg = config(
            r#"
            [hosts.mixed]
            hostname = "h"
            purpose  = "p"
            policy   = ["free", "def"]
            [hosts.mixed.def]
            deny = ["Bash(rm:*)"]
        "#,
        );
        assert_eq!(
            evaluator().evaluate(&cfg, "mixed", "rm file").unwrap(),
            Decision::Deny
        );
    }

    #[test]
    fn hook_only_policy_abstains_to_ask_while_stubbed() {
        let cfg = config(
            r#"
            [hosts.gated]
            hostname = "h"
            purpose  = "p"
            policy   = [{ hook = "~/hook.py" }]
        "#,
        );
        // Offline, the hook gate abstains; with no other gate the offline
        // path resolves to the default-mode fallback, `Ask`.
        assert_eq!(
            evaluator().evaluate(&cfg, "gated", "ls").unwrap(),
            Decision::Ask
        );
    }

    #[test]
    fn claude_gate_reads_user_settings() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ssh-mcp-test-claude-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{ "permissions": { "deny": ["Bash(sudo:*)"], "allow": ["Bash(ls:*)"] } }"#,
        )
        .unwrap();

        let ev = Evaluator::with_claude_settings_path(path.clone());
        let cfg = config(
            r#"
            [hosts.h]
            hostname = "h"
            purpose  = "p"
            policy   = ["claude"]
        "#,
        );
        assert_eq!(
            ev.evaluate(&cfg, "h", "sudo reboot").unwrap(),
            Decision::Deny
        );
        assert_eq!(ev.evaluate(&cfg, "h", "ls -la").unwrap(), Decision::Allow);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_path_subject_is_checked_against_the_rule_gates() {
        let cfg = config(
            r#"
            [hosts.staging]
            hostname = "h"
            purpose  = "p"
            policy   = ["def"]
            [hosts.staging.def]
            deny  = ["Read(//etc/**)"]
            allow = ["Edit(//srv/**)"]
        "#,
        );
        let host = cfg.host("staging").unwrap();
        let ev = evaluator();

        let denied = ev
            .evaluate_rule_gates(
                host,
                &Subject::Path {
                    tool: Tool::Read,
                    path: "/etc/shadow",
                },
            )
            .unwrap();
        assert_eq!(denied.decisions, vec![Decision::Deny]);

        let allowed = ev
            .evaluate_rule_gates(
                host,
                &Subject::Path {
                    tool: Tool::Write,
                    path: "/srv/app/data",
                },
            )
            .unwrap();
        assert_eq!(allowed.decisions, vec![Decision::Allow]);
    }

    #[test]
    fn check_user_path_applies_the_user_settings() {
        let path =
            std::env::temp_dir().join(format!("ssh-mcp-test-userpath-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{ "permissions": { "deny": ["Read(//secret/**)"], "allow": ["Edit(//work/**)"] } }"#,
        )
        .unwrap();
        let ev = Evaluator::with_claude_settings_path(path.clone());

        assert_eq!(
            ev.check_user_path(Tool::Read, "/secret/key").unwrap(),
            Decision::Deny
        );
        assert_eq!(
            ev.check_user_path(Tool::Write, "/work/output").unwrap(),
            Decision::Allow
        );
        assert_eq!(
            ev.check_user_path(Tool::Read, "/elsewhere/file").unwrap(),
            Decision::Unset
        );

        std::fs::remove_file(&path).ok();
    }
}
