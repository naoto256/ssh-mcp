//! The `ssh-mcp.toml` schema and loader.
//!
//! This file is the single source of truth for connection details, host
//! purpose, and per-host policy. The daemon is its only reader.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

/// Fallback exec timeout when neither the host nor `[defaults]` specifies one.
/// Generous enough to cover most builds; a host that needs longer should set
/// its own `exec_timeout_secs`, or run the work detached.
pub const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 600;

/// The three permission lists shared by the `def` and `claude` gates.
///
/// Both the TOML `[hosts.<alias>.def]` table and the user's `settings.json`
/// `permissions` object deserialize into this shape, so the evaluator has a
/// single internal representation regardless of the source format.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Permissions {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Permissions {
    /// Append another set's rules into this one.
    pub fn merge_from(&mut self, other: &Permissions) {
        self.allow.extend(other.allow.iter().cloned());
        self.ask.extend(other.ask.iter().cloned());
        self.deny.extend(other.deny.iter().cloned());
    }
}

/// A paramless gate kind, written as a bare string in the `policy` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGate {
    /// Constant allow.
    Free,
    /// Rules defined inline in the host's `[hosts.<alias>.def]` table.
    Def,
    /// The user-level rules from `~/.claude/settings.json`.
    Claude,
}

/// One gate in a host's `policy` array.
///
/// Paramless gates are written as strings (`"free"`, `"def"`, `"claude"`);
/// the parameterized gates are written as an inline table —
/// `{ hook = "..." }` for an external hook program, or `{ def = "name" }`
/// to reference a named ruleset defined in a top-level `[def.<name>]`
/// table. Named def references compose like any other gate: multiple of
/// them are evaluated strictest-wins together with whatever else the host
/// lists.
#[derive(Debug, Clone)]
pub enum Gate {
    Named(NamedGate),
    /// Delegate the decision to an external hook program.
    Hook {
        hook: String,
    },
    /// Apply the rules from `[def.<name>]`. Lets the same ruleset be
    /// shared across hosts without duplicating the lists.
    DefRef {
        name: String,
    },
}

impl Gate {
    /// The gate's kind as a short string, for display in `list_hosts`. The
    /// `hook` gate's program path and the `def` ref's name are intentionally
    /// not exposed — a model only needs to know "this is gated by an
    /// external hook" or "this host applies some def ruleset", not which
    /// program or which ruleset.
    pub fn kind(&self) -> &'static str {
        match self {
            Gate::Named(NamedGate::Free) => "free",
            Gate::Named(NamedGate::Def) => "def",
            Gate::Named(NamedGate::Claude) => "claude",
            Gate::Hook { .. } => "hook",
            Gate::DefRef { .. } => "def",
        }
    }
}

impl<'de> Deserialize<'de> for Gate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GateVisitor;

        impl<'de> Visitor<'de> for GateVisitor {
            type Value = Gate;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a gate name string, a { hook = \"...\" } table, or a { def = \"name\" } table",
                )
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Gate, E> {
                match value {
                    "free" => Ok(Gate::Named(NamedGate::Free)),
                    "def" => Ok(Gate::Named(NamedGate::Def)),
                    "claude" => Ok(Gate::Named(NamedGate::Claude)),
                    other => Err(E::custom(format!("unknown gate {other:?}"))),
                }
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Gate, A::Error> {
                let mut hook: Option<String> = None;
                let mut def_ref: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "hook" => hook = Some(map.next_value()?),
                        "def" => def_ref = Some(map.next_value()?),
                        other => {
                            return Err(de::Error::custom(format!("unknown gate field {other:?}")));
                        }
                    }
                }
                match (hook, def_ref) {
                    (Some(_), Some(_)) => Err(de::Error::custom(
                        "gate table sets both `hook` and `def`; use one per gate",
                    )),
                    (Some(h), None) => Ok(Gate::Hook { hook: h }),
                    (None, Some(n)) => Ok(Gate::DefRef { name: n }),
                    (None, None) => Err(de::Error::custom(
                        "gate table is missing one of `hook` or `def`",
                    )),
                }
            }
        }

        deserializer.deserialize_any(GateVisitor)
    }
}

/// A single host entry from `[hosts.<alias>]`.
#[derive(Debug, Clone, Deserialize)]
pub struct HostEntry {
    pub hostname: String,
    pub user: Option<String>,
    /// The SSH port; absent means the default, 22.
    pub port: Option<u16>,
    /// Aliases of the jump hosts to route through, nearest hop first.
    #[serde(default)]
    pub proxy_jump: Vec<String>,
    pub purpose: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// The unordered set of gates applied to this host.
    pub policy: Vec<Gate>,
    pub exec_timeout_secs: Option<u64>,
    /// Glob patterns `get_file` skips when downloading from this host — the
    /// remote tree is host-specific, so the download exclude is per-host.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Inline rules consumed by the `def` gate, from `[hosts.<alias>.def]`.
    pub def: Option<Permissions>,
}

/// The `[defaults]` table.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Defaults {
    pub exec_timeout_secs: Option<u64>,
    /// Glob patterns `put_file` skips when uploading — what to leave out of an
    /// upload (build output, VCS metadata) is a property of the source tree,
    /// not the host, so the upload exclude is global.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// The parsed `ssh-hosts.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostsConfig {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub hosts: HashMap<String, HostEntry>,
    /// Named, reusable `def` rulesets. A host references one through a
    /// `{ def = "name" }` gate in its `policy` array; multiple references
    /// compose strictest-wins. The lookup is by name; a missing entry is
    /// surfaced at evaluation time, not at config load.
    #[serde(default)]
    pub def: HashMap<String, Permissions>,
}

impl HostsConfig {
    /// Parse a config from a TOML string.
    pub fn parse(toml_str: &str) -> Result<Self> {
        toml::from_str(toml_str).context("failed to parse ssh-mcp.toml")
    }

    /// Look up a named def ruleset by name.
    pub fn named_def(&self, name: &str) -> Option<&Permissions> {
        self.def.get(name)
    }

    /// Read and parse the config from disk.
    ///
    /// The file is read fresh on every call: it is small, and dynamic reload
    /// avoids the complexity of cache invalidation.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&text)
    }

    /// Look up a host by its alias.
    pub fn host(&self, alias: &str) -> Option<&HostEntry> {
        self.hosts.get(alias)
    }

    /// The effective exec timeout for a host: its own override, else the
    /// global default, else the built-in fallback.
    pub fn exec_timeout_secs(&self, host: &HostEntry) -> u64 {
        host.exec_timeout_secs
            .or(self.defaults.exec_timeout_secs)
            .unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        [defaults]
        exec_timeout_secs = 120

        [hosts.build-rig]
        hostname = "10.0.5.12"
        user     = "ci"
        purpose  = "build server"
        tags     = ["build", "ci"]
        policy   = ["free"]

        [hosts.prod-db]
        hostname   = "10.0.1.30"
        user       = "deploy"
        proxy_jump = ["bastion-a"]
        purpose    = "database primary"
        tags       = ["db"]
        policy     = ["claude", { hook = "~/hooks/ask.py" }]
        exec_timeout_secs = 600

        [hosts.staging-api]
        hostname = "10.0.2.8"
        user     = "deploy"
        purpose  = "staging api"
        policy   = ["def"]
        [hosts.staging-api.def]
        allow = ["Bash(systemctl status:*)"]
        ask   = ["Bash(systemctl restart:*)"]
        deny  = ["Bash(rm:*)"]
    "#;

    #[test]
    fn parses_the_sample_config() {
        let config = HostsConfig::parse(SAMPLE).expect("sample config should parse");
        assert_eq!(config.hosts.len(), 3);
        assert_eq!(config.defaults.exec_timeout_secs, Some(120));
    }

    #[test]
    fn parses_paramless_and_hook_gates() {
        let config = HostsConfig::parse(SAMPLE).unwrap();
        let prod = config.host("prod-db").unwrap();
        assert_eq!(prod.policy.len(), 2);
        assert!(matches!(prod.policy[0], Gate::Named(NamedGate::Claude)));
        match &prod.policy[1] {
            Gate::Hook { hook } => assert_eq!(hook, "~/hooks/ask.py"),
            other => panic!("expected a hook gate, got {other:?}"),
        }
    }

    #[test]
    fn reads_inline_def_rules() {
        let config = HostsConfig::parse(SAMPLE).unwrap();
        let staging = config.host("staging-api").unwrap();
        let def = staging.def.as_ref().expect("def table should be present");
        assert_eq!(def.allow, ["Bash(systemctl status:*)"]);
        assert_eq!(def.deny, ["Bash(rm:*)"]);
    }

    #[test]
    fn host_timeout_overrides_default() {
        let config = HostsConfig::parse(SAMPLE).unwrap();
        let prod = config.host("prod-db").unwrap();
        let build = config.host("build-rig").unwrap();
        assert_eq!(config.exec_timeout_secs(prod), 600);
        assert_eq!(config.exec_timeout_secs(build), 120);
    }

    #[test]
    fn parses_exclude_lists() {
        let config = HostsConfig::parse(
            r#"
            [defaults]
            exclude = ["target", ".git"]

            [hosts.boxed]
            hostname = "h"
            purpose  = "p"
            policy   = ["free"]
            exclude  = ["*.log"]

            [hosts.bare]
            hostname = "h"
            purpose  = "p"
            policy   = ["free"]
        "#,
        )
        .unwrap();
        assert_eq!(config.defaults.exclude, ["target", ".git"]);
        assert_eq!(config.host("boxed").unwrap().exclude, ["*.log"]);
        // An absent exclude list defaults to empty.
        assert!(config.host("bare").unwrap().exclude.is_empty());
    }

    #[test]
    fn rejects_an_unknown_gate_name() {
        let bad = r#"
            [hosts.x]
            hostname = "h"
            purpose  = "p"
            policy   = ["bogus"]
        "#;
        assert!(HostsConfig::parse(bad).is_err());
    }

    #[test]
    fn parses_a_named_def_ref_and_its_table() {
        // A host references a top-level `[def.NAME]` ruleset through a
        // `{ def = "NAME" }` gate. The ruleset itself lives under
        // `[def.NAME]` and is shared across every host that references it.
        let config = HostsConfig::parse(
            r#"
            [hosts.staging]
            hostname = "h"
            purpose  = "p"
            policy   = [{ def = "shared" }, "claude"]

            [def.shared]
            allow = ["Bash(systemctl status:*)"]
            deny  = ["Bash(rm:*)"]
        "#,
        )
        .unwrap();
        let host = config.host("staging").unwrap();
        assert_eq!(host.policy.len(), 2);
        match &host.policy[0] {
            Gate::DefRef { name } => assert_eq!(name, "shared"),
            other => panic!("expected a DefRef gate, got {other:?}"),
        }
        let shared = config.named_def("shared").expect("named def should parse");
        assert_eq!(shared.allow, ["Bash(systemctl status:*)"]);
        assert_eq!(shared.deny, ["Bash(rm:*)"]);
    }

    #[test]
    fn rejects_a_gate_table_with_both_hook_and_def() {
        // A single gate table must specify one kind; the two are
        // independent gates and should appear as separate array elements
        // if you want both.
        let bad = r#"
            [hosts.x]
            hostname = "h"
            purpose  = "p"
            policy   = [{ hook = "/bin/h", def = "shared" }]

            [def.shared]
            allow = ["Bash(ls)"]
        "#;
        assert!(HostsConfig::parse(bad).is_err());
    }
}
