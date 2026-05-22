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
use super::permission::PermissionSet;
use crate::config::{Gate, HostsConfig, NamedGate, Permissions};

/// The subset of `~/.claude/settings.json` the `claude` gate needs.
#[derive(Debug, Default, Deserialize)]
struct ClaudeSettings {
    #[serde(default)]
    permissions: Permissions,
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

    /// Evaluate a command against a host's policy.
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
        self.evaluate_policy(&host.policy, host.def.as_ref(), command)
    }

    fn evaluate_policy(
        &self,
        gates: &[Gate],
        def: Option<&Permissions>,
        command: &str,
    ) -> Result<Decision> {
        // An empty gate set is equivalent to `free`.
        if gates.is_empty() {
            return Ok(Decision::Allow);
        }

        // The `def` and `claude` gates share the Claude Code rule grammar, so
        // their rules are merged into one set and evaluated once.
        let mut merged = Permissions::default();
        let mut has_rule_gate = false;
        let mut decisions: Vec<Decision> = Vec::new();

        for gate in gates {
            match gate {
                Gate::Named(NamedGate::Free) => decisions.push(Decision::Allow),
                Gate::Named(NamedGate::Def) => {
                    if let Some(rules) = def {
                        merged.merge_from(rules);
                    }
                    has_rule_gate = true;
                }
                Gate::Named(NamedGate::Claude) => {
                    merged.merge_from(&self.load_claude_permissions()?);
                    has_rule_gate = true;
                }
                Gate::Hook { .. } => {
                    // The hook gate is not yet wired up; it abstains for now.
                    decisions.push(Decision::Unset);
                }
            }
        }

        if has_rule_gate {
            let set = PermissionSet::from_permissions(&merged)?;
            decisions.push(set.evaluate_command(command));
        }

        Ok(combine_gates(&decisions))
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

/// Combine gate decisions: the strictest opinion wins, abstentions are
/// ignored, and a policy where every gate abstains fails closed to `Deny`.
fn combine_gates(decisions: &[Decision]) -> Decision {
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
        .unwrap_or(Decision::Deny)
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
    fn def_gate_with_no_matching_rule_fails_closed() {
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
        assert_eq!(
            evaluator().evaluate(&cfg, "staging", "whoami").unwrap(),
            Decision::Deny
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
    fn hook_only_policy_fails_closed_while_stubbed() {
        let cfg = config(
            r#"
            [hosts.gated]
            hostname = "h"
            purpose  = "p"
            policy   = [{ hook = "~/hook.py" }]
        "#,
        );
        assert_eq!(
            evaluator().evaluate(&cfg, "gated", "ls").unwrap(),
            Decision::Deny
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
}
