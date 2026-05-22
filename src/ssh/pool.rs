//! The SSH connection pool and command execution.
//!
//! One russh connection per host is kept and reused across `exec` calls;
//! channels are opened per command. Execution is stateless — no cwd or shell
//! state carries between commands — so a reconnect restores nothing and is
//! transparent.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::{Channel, ChannelMsg, client};
use tokio::sync::Mutex;

use super::handler::StrictHostKey;
use crate::config::{HostEntry, HostsConfig};

/// SSH listens here; the inventory has no per-host port override yet.
const SSH_PORT: u16 = 22;

/// The result of running one remote command.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    /// The remote exit code, or `-1` if the command was signalled or the
    /// channel closed without reporting one.
    pub exit_code: i32,
}

/// A pool of live SSH connections, keyed by host alias.
pub struct ConnectionPool {
    connections: Mutex<HashMap<String, Arc<client::Handle<StrictHostKey>>>>,
    config: Arc<client::Config>,
    known_hosts: PathBuf,
}

impl ConnectionPool {
    /// Create an empty pool that verifies hosts against `~/.ssh/known_hosts`.
    pub fn new() -> Result<Self> {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        Ok(Self {
            connections: Mutex::new(HashMap::new()),
            config: Arc::new(client::Config::default()),
            known_hosts: PathBuf::from(home).join(".ssh").join("known_hosts"),
        })
    }

    /// Run a command on a host and return its output.
    ///
    /// The connection is reused if pooled. A dead pooled connection is
    /// detected when the channel fails to open and is replaced once; because
    /// the command runs only after a channel is open, it executes at most
    /// once even across a reconnect.
    pub async fn exec(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        command: &str,
        timeout: Duration,
    ) -> Result<ExecOutput> {
        let handle = self.get_or_connect(config, host_alias).await?;
        let mut channel = match handle.channel_open_session().await {
            Ok(channel) => channel,
            Err(_) => {
                self.evict(host_alias).await;
                let handle = self.get_or_connect(config, host_alias).await?;
                handle
                    .channel_open_session()
                    .await
                    .context("failed to open a channel after reconnecting")?
            }
        };
        run_command(&mut channel, command, timeout).await
    }

    async fn evict(&self, host_alias: &str) {
        self.connections.lock().await.remove(host_alias);
    }

    async fn get_or_connect(
        &self,
        config: &HostsConfig,
        host_alias: &str,
    ) -> Result<Arc<client::Handle<StrictHostKey>>> {
        let mut connections = self.connections.lock().await;
        if let Some(handle) = connections.get(host_alias) {
            return Ok(handle.clone());
        }
        let handle = Arc::new(self.connect_chain(config, host_alias).await?);
        connections.insert(host_alias.to_string(), handle.clone());
        Ok(handle)
    }

    /// Establish a connection to a host, tunneling through its jump hosts.
    async fn connect_chain(
        &self,
        config: &HostsConfig,
        host_alias: &str,
    ) -> Result<client::Handle<StrictHostKey>> {
        let target = resolve(config, host_alias)?;

        // The hop sequence: each jump host, nearest first, then the target.
        let mut hops: Vec<&str> = target.proxy_jump.iter().map(String::as_str).collect();
        hops.push(host_alias);

        // The first hop is reached by a direct TCP connection.
        let first = resolve(config, hops[0])?;
        let mut handle = client::connect(
            self.config.clone(),
            (first.hostname.as_str(), SSH_PORT),
            self.host_key_handler(&first.hostname),
        )
        .await
        .with_context(|| format!("failed to connect to {:?}", hops[0]))?;
        authenticate(&mut handle, &user_of(first)).await?;

        // Each later hop is tunneled through the connection before it.
        for &alias in &hops[1..] {
            let hop = resolve(config, alias)?;
            let tunnel = handle
                .channel_open_direct_tcpip(
                    hop.hostname.clone(),
                    u32::from(SSH_PORT),
                    "127.0.0.1",
                    0,
                )
                .await
                .with_context(|| format!("failed to open a tunnel to {alias:?}"))?;
            let mut next = client::connect_stream(
                self.config.clone(),
                tunnel.into_stream(),
                self.host_key_handler(&hop.hostname),
            )
            .await
            .with_context(|| format!("SSH handshake with {alias:?} failed"))?;
            authenticate(&mut next, &user_of(hop)).await?;
            handle = next;
        }
        Ok(handle)
    }

    fn host_key_handler(&self, hostname: &str) -> StrictHostKey {
        StrictHostKey::new(hostname, SSH_PORT, self.known_hosts.clone())
    }
}

fn resolve<'a>(config: &'a HostsConfig, alias: &str) -> Result<&'a HostEntry> {
    config
        .host(alias)
        .with_context(|| format!("host {alias:?} is not in the inventory"))
}

/// The login user for a host: its configured user, else `$USER`.
fn user_of(host: &HostEntry) -> String {
    host.user
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".to_string())
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

/// Run a command on an open channel, bounded by `timeout`.
async fn run_command(
    channel: &mut Channel<client::Msg>,
    command: &str,
    timeout: Duration,
) -> Result<ExecOutput> {
    match tokio::time::timeout(timeout, collect_output(channel, command)).await {
        Ok(result) => result,
        Err(_) => {
            let _ = channel.close().await;
            bail!("command timed out after {} seconds", timeout.as_secs())
        }
    }
}

async fn collect_output(channel: &mut Channel<client::Msg>, command: &str) -> Result<ExecOutput> {
    channel
        .exec(true, command)
        .await
        .context("the remote exec request failed")?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = -1;

    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
            _ => {}
        }
    }

    Ok(ExecOutput {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit_code,
    })
}
