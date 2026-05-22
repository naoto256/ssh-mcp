//! Establishing russh connections, including multi-hop ProxyJump chains.
//!
//! The connection logic is shared by the pool — which caches one connection
//! per host — and the rsync transport bridge, which opens a fresh connection
//! of its own. Both build a connection from a resolved hop chain, so neither
//! the pool nor the bridge needs to reach into the inventory while connecting.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::client;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use serde::{Deserialize, Serialize};

use super::handler::StrictHostKey;
use crate::config::{HostEntry, HostsConfig};

/// The SSH port used when a host does not specify one.
const DEFAULT_SSH_PORT: u16 = 22;

/// How long to wait for a connection — TCP, the SSH handshake, and agent auth,
/// across every ProxyJump hop — to be established before giving up.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Send an SSH keepalive after this much silence: it keeps a long no-output
/// command from being dropped by an idle network middlebox, and lets russh
/// notice a frozen peer (russh closes the connection after `keepalive_max`).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// One hop's resolved connection parameters — enough to dial it without the
/// inventory. The `alias` is carried only for error messages: a failure must
/// never surface a hostname or an address to the model.
///
/// Serializable so the daemon can hand a resolved chain to the rsync bridge,
/// keeping the daemon the only reader of the inventory file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    /// The inventory alias, used in error messages — never the hostname.
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
}

/// Resolve a host's connection chain from the inventory: each jump hop,
/// nearest first, then the target host itself.
pub fn resolve_chain(config: &HostsConfig, host_alias: &str) -> Result<Vec<Hop>> {
    let target = resolve(config, host_alias)?;
    let mut aliases: Vec<&str> = target.proxy_jump.iter().map(String::as_str).collect();
    aliases.push(host_alias);
    aliases
        .into_iter()
        .map(|alias| {
            let entry = resolve(config, alias)?;
            Ok(Hop {
                alias: alias.to_string(),
                hostname: entry.hostname.clone(),
                port: port_of(entry),
                user: user_of(entry),
            })
        })
        .collect()
}

fn resolve<'a>(config: &'a HostsConfig, alias: &str) -> Result<&'a HostEntry> {
    config
        .host(alias)
        .with_context(|| format!("host {alias:?} is not in the inventory"))
}

/// The SSH port for a host: its configured port, else the default.
fn port_of(host: &HostEntry) -> u16 {
    host.port.unwrap_or(DEFAULT_SSH_PORT)
}

/// The login user for a host: its configured user, else `$USER`.
fn user_of(host: &HostEntry) -> String {
    host.user
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".to_string())
}

/// Builds russh connections from a resolved hop chain. Shared by the
/// connection pool and the rsync transport bridge.
pub struct SshConnector {
    config: Arc<client::Config>,
    known_hosts: PathBuf,
}

impl SshConnector {
    /// A connector that verifies hosts against `~/.ssh/known_hosts`.
    pub fn new() -> Result<Self> {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        Ok(Self {
            config: Arc::new(client::Config {
                keepalive_interval: Some(KEEPALIVE_INTERVAL),
                ..Default::default()
            }),
            known_hosts: PathBuf::from(home).join(".ssh").join("known_hosts"),
        })
    }

    /// Connect along a resolved hop chain, tunneling each hop through the one
    /// before it. The chain must be non-empty; its last element is the target.
    pub async fn connect(&self, chain: &[Hop]) -> Result<client::Handle<StrictHostKey>> {
        let Some((first, rest)) = chain.split_first() else {
            bail!("the connection chain is empty");
        };

        // The first hop is reached by a direct TCP connection.
        let mut handle = client::connect(
            self.config.clone(),
            (first.hostname.as_str(), first.port),
            self.host_key_handler(&first.hostname, first.port),
        )
        .await
        .with_context(|| format!("failed to connect to {:?}", first.alias))?;
        authenticate(&mut handle, &first.user).await?;

        // Each later hop is tunneled through the connection before it.
        for hop in rest {
            let tunnel = handle
                .channel_open_direct_tcpip(
                    hop.hostname.clone(),
                    u32::from(hop.port),
                    "127.0.0.1",
                    0,
                )
                .await
                .with_context(|| format!("failed to open a tunnel to {:?}", hop.alias))?;
            let mut next = client::connect_stream(
                self.config.clone(),
                tunnel.into_stream(),
                self.host_key_handler(&hop.hostname, hop.port),
            )
            .await
            .with_context(|| format!("SSH handshake with {:?} failed", hop.alias))?;
            authenticate(&mut next, &hop.user).await?;
            handle = next;
        }
        Ok(handle)
    }

    fn host_key_handler(&self, hostname: &str, port: u16) -> StrictHostKey {
        StrictHostKey::new(hostname, port, self.known_hosts.clone())
    }
}

/// Authenticate a connection using the keys held by the SSH agent. Each hop
/// authenticates locally, so no key ever leaves this machine.
async fn authenticate(handle: &mut client::Handle<StrictHostKey>, user: &str) -> Result<()> {
    let mut agent = AgentClient::connect_env()
        .await
        .context("could not reach the SSH agent ($SSH_AUTH_SOCK)")?;
    let identities = agent
        .request_identities()
        .await
        .context("could not list SSH agent identities")?;
    if identities.is_empty() {
        bail!("the SSH agent holds no identities");
    }
    let hash_alg = handle.best_supported_rsa_hash().await?.flatten();

    for identity in identities {
        let key = match identity {
            AgentIdentity::PublicKey { key, .. } => key,
            AgentIdentity::Certificate { .. } => continue,
        };
        let result = handle
            .authenticate_publickey_with(user, key, hash_alg, &mut agent)
            .await?;
        if result.success() {
            return Ok(());
        }
    }
    bail!("SSH agent authentication failed for user {user:?}")
}
