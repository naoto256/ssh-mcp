//! Strict host-key verification.

use std::path::PathBuf;

use russh::client;
use russh::keys::check_known_hosts_path;
use russh::keys::ssh_key;

/// A russh client handler that verifies the server's host key against
/// `~/.ssh/known_hosts`. An unknown host or a key mismatch is rejected —
/// there is no trust-on-first-use, so every host in the inventory must
/// already be known.
pub struct StrictHostKey {
    host: String,
    port: u16,
    known_hosts: PathBuf,
}

impl StrictHostKey {
    pub fn new(host: impl Into<String>, port: u16, known_hosts: PathBuf) -> Self {
        Self {
            host: host.into(),
            port,
            known_hosts,
        }
    }
}

impl client::Handler for StrictHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // `check_known_hosts_path` returns `Ok(true)` on a match, `Ok(false)`
        // when the host is absent, and `Err` on a key mismatch. Anything but
        // a clean match is a rejection.
        Ok(
            check_known_hosts_path(&self.host, self.port, server_public_key, &self.known_hosts)
                .unwrap_or(false),
        )
    }
}
