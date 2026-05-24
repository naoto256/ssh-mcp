//! The audit log: one JSON line per policy decision, command run, and transfer.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
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

/// One audit record. Policy decisions, command executions, and file transfers
/// are all logged, tagged by `event` so a reader can tell them apart and
/// correlate them by host.
#[derive(Serialize)]
#[serde(tag = "event", rename_all = "lowercase")]
enum AuditEntry<'a> {
    /// A policy decision the daemon returned to a hook query.
    Decision {
        timestamp: String,
        host: &'a str,
        command: String,
        permission_mode: &'a str,
        decision: &'a str,
    },
    /// A command that was run and its outcome.
    Exec {
        timestamp: String,
        host: &'a str,
        command: String,
        exit_code: Option<i32>,
        error: Option<&'a str>,
    },
    /// A file transfer and its outcome.
    Transfer {
        timestamp: String,
        host: &'a str,
        direction: &'a str,
        remote_path: &'a str,
        local_path: &'a str,
        bytes: Option<u64>,
        error: Option<&'a str>,
    },
}

/// Appends decision, exec, and transfer records to a JSONL file.
#[derive(Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Record a policy decision, including the permission mode it was made
    /// under. The command is masked before it is written.
    pub fn record_decision(
        &self,
        host: &str,
        command: &str,
        permission_mode: &str,
        decision: &str,
    ) {
        self.write(AuditEntry::Decision {
            timestamp: jiff::Timestamp::now().to_string(),
            host,
            command: mask_secrets(command),
            permission_mode,
            decision,
        });
    }

    /// Record one exec and its outcome. The command is masked before writing.
    pub fn record_exec(
        &self,
        host: &str,
        command: &str,
        exit_code: Option<i32>,
        error: Option<&str>,
    ) {
        self.write(AuditEntry::Exec {
            timestamp: jiff::Timestamp::now().to_string(),
            host,
            command: mask_secrets(command),
            exit_code,
            error,
        });
    }

    /// Record one file transfer and its outcome.
    pub fn record_transfer(
        &self,
        direction: &str,
        host: &str,
        remote_path: &str,
        local_path: &str,
        bytes: Option<u64>,
        error: Option<&str>,
    ) {
        self.write(AuditEntry::Transfer {
            timestamp: jiff::Timestamp::now().to_string(),
            host,
            direction,
            remote_path,
            local_path,
            bytes,
            error,
        });
    }

    /// Append one entry. A logging failure must never break a request, so it
    /// is reported to stderr and dropped.
    fn write(&self, entry: AuditEntry<'_>) {
        if let Err(e) = self.append(&entry) {
            eprintln!("ssh-mcp: could not write the audit log: {e:#}");
        }
    }

    fn append(&self, entry: &AuditEntry<'_>) -> Result<()> {
        let mut line = serde_json::to_string(entry)?;
        line.push('\n');
        // Owner-only at the file level too: the parent `~/.ssh/ssh-mcp/`
        // is already 0o700, but pinning the file mode keeps the record
        // private even if someone later loosens the directory.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
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
    fn writes_a_transfer_entry() {
        let path =
            std::env::temp_dir().join(format!("ssh-mcp-audit-xfer-{}.jsonl", std::process::id()));
        let log = AuditLog::new(path.clone());
        log.record_transfer(
            "get",
            "build-rig",
            "/remote/f",
            "/local/f",
            Some(2048),
            None,
        );

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"event\":\"transfer\""));
        assert!(contents.contains("\"direction\":\"get\""));
        assert!(contents.contains("\"bytes\":2048"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn leaves_ordinary_assignments_alone() {
        assert_eq!(mask_secrets("LANG=C make"), "LANG=C make");
        assert_eq!(mask_secrets("MONKEY=1 echo hi"), "MONKEY=1 echo hi");
    }

    #[test]
    fn writes_tagged_jsonl_lines() {
        let path = std::env::temp_dir().join(format!("ssh-mcp-audit-{}.jsonl", std::process::id()));
        let log = AuditLog::new(path.clone());
        log.record_exec("build-rig", "TOKEN=secret echo hi", Some(0), None);
        log.record_decision("prod-db", "rm -rf /", "default", "deny");

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"event\":\"exec\""));
        assert!(contents.contains("\"event\":\"decision\""));
        assert!(contents.contains("\"host\":\"build-rig\""));
        assert!(contents.contains("\"permission_mode\":\"default\""));
        assert!(contents.contains("\"decision\":\"deny\""));
        // The secret value is masked in both record kinds.
        assert!(contents.contains("TOKEN=***"));
        assert!(!contents.contains("secret"));

        std::fs::remove_file(&path).ok();
    }
}
