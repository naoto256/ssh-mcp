//! The exec audit log: one JSON line per command run.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Serialize;

/// Matches `NAME=value` assignments whose name looks secret-bearing, so the
/// value can be masked before the command is written to the log.
static SECRET_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|API_?KEY))=(\S+)")
        .expect("the secret-assignment regex is valid")
});

/// Replace the values of secret-looking environment assignments with `***`.
pub fn mask_secrets(command: &str) -> String {
    SECRET_ASSIGNMENT
        .replace_all(command, "$1=***")
        .into_owned()
}

#[derive(Serialize)]
struct AuditEntry<'a> {
    timestamp: String,
    host: &'a str,
    command: String,
    exit_code: Option<i32>,
    error: Option<&'a str>,
}

/// Appends exec records to a JSONL file.
#[derive(Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The default audit log location, `~/.ssh/ssh-mcp-audit.jsonl`.
    pub fn at_default_location() -> Result<Self> {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        Ok(Self::new(
            PathBuf::from(home).join(".ssh").join("ssh-mcp-audit.jsonl"),
        ))
    }

    /// Record one exec. The command is masked before it is written. A logging
    /// failure must never break exec, so it is reported to stderr and dropped.
    pub fn record(&self, host: &str, command: &str, exit_code: Option<i32>, error: Option<&str>) {
        let entry = AuditEntry {
            timestamp: jiff::Timestamp::now().to_string(),
            host,
            command: mask_secrets(command),
            exit_code,
            error,
        };
        if let Err(e) = self.append(&entry) {
            eprintln!("ssh-mcp: could not write the audit log: {e:#}");
        }
    }

    fn append(&self, entry: &AuditEntry<'_>) -> Result<()> {
        let mut line = serde_json::to_string(entry)?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open {}", self.path.display()))?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_secret_assignments() {
        assert_eq!(
            mask_secrets("GITHUB_TOKEN=ghp_abc123 gh pr list"),
            "GITHUB_TOKEN=*** gh pr list"
        );
        assert_eq!(
            mask_secrets("DB_PASSWORD=hunter2 psql"),
            "DB_PASSWORD=*** psql"
        );
        assert_eq!(mask_secrets("API_KEY=xyz curl"), "API_KEY=*** curl");
    }

    #[test]
    fn leaves_ordinary_assignments_alone() {
        assert_eq!(mask_secrets("LANG=C make"), "LANG=C make");
        assert_eq!(mask_secrets("MONKEY=1 echo hi"), "MONKEY=1 echo hi");
    }

    #[test]
    fn writes_a_jsonl_line() {
        let path = std::env::temp_dir().join(format!("ssh-mcp-audit-{}.jsonl", std::process::id()));
        let log = AuditLog::new(path.clone());
        log.record("build-rig", "TOKEN=secret echo hi", Some(0), None);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"host\":\"build-rig\""));
        assert!(contents.contains("TOKEN=***"));
        assert!(!contents.contains("secret"));
        std::fs::remove_file(&path).ok();
    }
}
