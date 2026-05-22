//! The SSH connection pool and command execution.
//!
//! One russh connection per host is kept and reused across `exec` calls;
//! channels are opened per command. Execution is stateless — no cwd or shell
//! state carries between commands — so a reconnect restores nothing and is
//! transparent.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::{Channel, ChannelMsg, client};
use tokio::sync::Mutex;

use super::connect::{CONNECT_TIMEOUT, SshConnector, resolve_chain};
use super::handler::StrictHostKey;
use super::transfer::{self, TransferStats};
use crate::config::HostsConfig;

/// How long to wait for a session channel to open before treating the pooled
/// connection as dead — a healthy connection opens one in a single round trip.
const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(15);

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
    connector: SshConnector,
}

impl ConnectionPool {
    /// Create an empty pool that verifies hosts against `~/.ssh/known_hosts`.
    pub fn new() -> Result<Self> {
        Ok(Self {
            connections: Mutex::new(HashMap::new()),
            connector: SshConnector::new()?,
        })
    }

    /// Run a command on a host and return its output.
    ///
    /// The connection is reused if pooled. A dead pooled connection is detected
    /// when the channel fails to open or times out, and is replaced once;
    /// because the command runs only after a channel is open, it executes at
    /// most once even across a reconnect.
    pub async fn exec(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        command: &str,
        timeout: Duration,
    ) -> Result<ExecOutput> {
        let mut channel = self.open_session(config, host_alias).await?;
        run_command(&mut channel, command, timeout).await
    }

    /// Download a remote file or directory into `local_path`, via `tar`.
    pub async fn get_file(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        remote_path: &str,
        local_path: &Path,
        timeout: Duration,
    ) -> Result<TransferStats> {
        let channel = self.open_session(config, host_alias).await?;
        transfer::download(channel, remote_path, local_path, timeout).await
    }

    /// Upload a local file or directory to `remote_path`, via `tar`.
    pub async fn put_file(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        local_path: &Path,
        remote_path: &str,
        timeout: Duration,
    ) -> Result<TransferStats> {
        let channel = self.open_session(config, host_alias).await?;
        transfer::upload(channel, local_path, remote_path, timeout).await
    }

    /// Open a fresh channel on a host's pooled connection. A dead pooled
    /// connection is detected when the channel fails to open or times out, and
    /// is replaced once before retrying.
    async fn open_session(
        &self,
        config: &HostsConfig,
        host_alias: &str,
    ) -> Result<Channel<client::Msg>> {
        let handle = self.get_or_connect(config, host_alias).await?;
        match open_channel(&handle).await {
            Ok(channel) => Ok(channel),
            Err(_) => {
                // The pooled connection looks dead; drop it and reconnect once.
                self.evict(host_alias).await;
                let handle = self.get_or_connect(config, host_alias).await?;
                open_channel(&handle)
                    .await
                    .context("failed to open a channel after reconnecting")
            }
        }
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
        let chain = resolve_chain(config, host_alias)?;
        // Bound the whole connection setup (TCP, handshake, auth, every hop):
        // russh imposes no handshake timeout, so a stalled peer would hang.
        let handle =
            match tokio::time::timeout(CONNECT_TIMEOUT, self.connector.connect(&chain)).await {
                Ok(result) => Arc::new(result?),
                Err(_) => bail!(
                    "connecting to {host_alias:?} timed out after {} seconds",
                    CONNECT_TIMEOUT.as_secs()
                ),
            };
        connections.insert(host_alias.to_string(), handle.clone());
        Ok(handle)
    }
}

/// Open a session channel, bounded so a frozen pooled connection is detected
/// quickly instead of hanging. A timeout is returned as an error so the caller
/// drops the connection and reconnects.
async fn open_channel(handle: &client::Handle<StrictHostKey>) -> Result<Channel<client::Msg>> {
    match tokio::time::timeout(CHANNEL_OPEN_TIMEOUT, handle.channel_open_session()).await {
        Ok(Ok(channel)) => Ok(channel),
        Ok(Err(e)) => Err(e).context("opening a session channel"),
        Err(_) => bail!(
            "opening a session channel timed out after {} seconds; the pooled \
             connection is unresponsive",
            CHANNEL_OPEN_TIMEOUT.as_secs()
        ),
    }
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
