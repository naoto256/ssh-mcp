//! Strict host-key verification.
//!
//! Two verification paths live here, chosen per-connection:
//!
//! 1. **Pinned key.** When the inventory entry carries a `host_key`, the
//!    server's live key must byte-match the parsed pin. No fallback to
//!    `known_hosts`: a mismatch is a clean reject. This is the path used by
//!    `propose_host`-created ephemeral hosts so they never have to touch
//!    `~/.ssh/known_hosts`.
//! 2. **`known_hosts` fallback.** When no pin is configured, behaviour is
//!    unchanged from before — `~/.ssh/known_hosts` is the source of truth,
//!    and any miss or mismatch is a reject.

use std::path::PathBuf;

use russh::client;
use russh::keys::check_known_hosts_path;
use russh::keys::ssh_key;

/// A russh client handler that verifies the server's host key. The pin
/// (if any) wins; otherwise `~/.ssh/known_hosts` is consulted.
pub struct StrictHostKey {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    /// Optional pinned key parsed from the inventory's `host_key` field.
    /// Held as the already-parsed `ssh_key::PublicKey` so the runtime check
    /// stays a single byte comparison.
    pinned: Option<ssh_key::PublicKey>,
}

impl StrictHostKey {
    /// A handler that consults `~/.ssh/known_hosts` (no pin).
    pub fn new(host: impl Into<String>, port: u16, known_hosts: PathBuf) -> Self {
        Self {
            host: host.into(),
            port,
            known_hosts,
            pinned: None,
        }
    }

    /// A handler that accepts only `pinned`, with no `known_hosts` fallback.
    /// `known_hosts` is still passed in case the caller wants a uniform
    /// constructor, but it is never consulted when a pin is set.
    pub fn with_pinned(
        host: impl Into<String>,
        port: u16,
        known_hosts: PathBuf,
        pinned: ssh_key::PublicKey,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            known_hosts,
            pinned: Some(pinned),
        }
    }
}

impl client::Handler for StrictHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Pinned path: byte-exact match against the parsed key, no fallback.
        if let Some(pinned) = &self.pinned {
            return Ok(pinned == server_public_key);
        }
        // `check_known_hosts_path` returns `Ok(true)` on a match, `Ok(false)`
        // when the host is absent, and `Err` on a key mismatch. Anything but
        // a clean match is a rejection.
        Ok(
            check_known_hosts_path(&self.host, self.port, server_public_key, &self.known_hosts)
                .unwrap_or(false),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client::Handler;

    // Two distinct, throwaway ed25519 public keys. Generated locally — never
    // used to auth anywhere.
    const KEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDUPtEBVQ314blItt/QQgFgNvrPgU/eEZY1b6kj9IgiF a@example";
    const KEY_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3O4kY9MJq6lJYjK7uoWfGmRyT4ZE6f9wL5tNvX2sCp b@example";

    fn parse(s: &str) -> ssh_key::PublicKey {
        ssh_key::PublicKey::from_openssh(s).expect("test key parses")
    }

    #[tokio::test]
    async fn pinned_match_accepts() {
        let key = parse(KEY_A);
        let mut h = StrictHostKey::with_pinned("h", 22, PathBuf::from("/dev/null"), key.clone());
        assert!(h.check_server_key(&key).await.unwrap());
    }

    #[tokio::test]
    async fn pinned_mismatch_rejects_without_fallback() {
        let pinned = parse(KEY_A);
        let live = parse(KEY_B);
        // `known_hosts` points at a missing path; even so, the result must be
        // a clean false (reject) rather than falling through.
        let mut h = StrictHostKey::with_pinned(
            "h",
            22,
            PathBuf::from("/tmp/this-path-does-not-exist-xxxxxx"),
            pinned,
        );
        assert!(!h.check_server_key(&live).await.unwrap());
    }

    #[tokio::test]
    async fn unpinned_falls_back_to_known_hosts() {
        // An unpinned handler with an empty `known_hosts` should reject any
        // key it sees — the fallback path returns false on "host absent".
        let live = parse(KEY_A);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut h = StrictHostKey::new("h", 22, tmp.path().to_path_buf());
        assert!(!h.check_server_key(&live).await.unwrap());
    }
}
