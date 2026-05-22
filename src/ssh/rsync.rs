//! The rsync fast path: a delta transfer driven by the system `rsync`.
//!
//! When both ends have `rsync`, a transfer reuses it instead of the tar path:
//! rsync only sends the parts of a file that changed, so re-transfers are
//! cheap. ssh-mcp drives the local `rsync` binary and points its transport
//! (`-e`) at the `rsh-bridge` subcommand, which carries the rsync protocol
//! over a russh connection. The remote runs its own stock `rsync --server`.
//!
//! There is no Rust crate that speaks the rsync wire protocol under a
//! permissive licence, so the local `rsync` binary is the protocol client.
//! When either end lacks `rsync`, the caller falls back to the tar path.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tempfile::NamedTempFile;
use tokio::process::Command;

use super::ConnectionPool;
use super::connect::{Hop, resolve_chain};
use super::transfer::{TransferStats, local_parent, promote, shell_quote, split_remote, tree_size};
use crate::bridge::CHAIN_ENV;
use crate::config::HostsConfig;

/// How long to allow for a quick remote probe command.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// The placeholder host token in the rsync remote spec. The bridge ignores it
/// — the real connection comes from the chain file — but rsync needs a
/// `host:path` shape to recognise a remote transfer.
const REMOTE_TOKEN: &str = "ssh-mcp";

/// Whether the rsync fast path can be used for a host: `rsync` must be present
/// both locally and on the remote.
pub async fn usable(pool: &ConnectionPool, config: &HostsConfig, host: &str) -> bool {
    if !local_available().await {
        return false;
    }
    remote_available(pool, config, host).await.unwrap_or(false)
}

/// Download a remote file or directory into `local_path` with rsync, replacing
/// `local_path` if it already exists.
pub async fn download(
    pool: &ConnectionPool,
    config: &HostsConfig,
    host: &str,
    remote_path: &str,
    local_path: &Path,
    timeout: Duration,
) -> Result<TransferStats> {
    let _ = pool;
    let parent = local_parent(local_path);
    if !parent.is_dir() {
        bail!("the local directory {} does not exist", parent.display());
    }
    let (_dir, base) = split_remote(remote_path)?;

    let chain_file = write_chain(config, host)?;
    // Stage beside the destination — same filesystem, so the final move is an
    // atomic rename. A trailing slash makes rsync drop the source *inside* the
    // staging directory, named after its own basename, for files and dirs alike.
    let staging = tempfile::tempdir_in(parent).context("creating a staging directory")?;
    let staging_arg = format!("{}/", staging.path().display());

    let mut command = rsync_command(&chain_file)?;
    command
        .arg("--")
        .arg(format!("{REMOTE_TOKEN}:{remote_path}"))
        .arg(&staging_arg);
    finish_rsync(command, timeout).await?;

    let produced = staging.path().join(&base);
    if !produced.exists() {
        bail!("rsync did not produce the expected entry {base:?}");
    }
    let bytes = tree_size(&produced);
    promote(&produced, local_path)?;
    Ok(TransferStats { bytes })
}

/// Upload a local file or directory to `remote_path` with rsync, replacing
/// `remote_path` if it already exists.
pub async fn upload(
    pool: &ConnectionPool,
    config: &HostsConfig,
    host: &str,
    local_path: &Path,
    remote_path: &str,
    timeout: Duration,
) -> Result<TransferStats> {
    if !local_path.exists() {
        bail!("the local path {} does not exist", local_path.display());
    }
    let (remote_dir, _base) = split_remote(remote_path)?;

    // rsync does not create missing parent directories; make the parent first.
    let mkdir = pool
        .exec(
            config,
            host,
            &format!("mkdir -p -- {}", shell_quote(&remote_dir)),
            PROBE_TIMEOUT,
        )
        .await
        .context("preparing the remote directory")?;
    if mkdir.exit_code != 0 {
        bail!(
            "could not create the remote directory: {}",
            mkdir.stderr.trim()
        );
    }

    let chain_file = write_chain(config, host)?;
    let mut command = rsync_command(&chain_file)?;
    command.arg("--");
    // A directory is sent with trailing slashes so its *contents* land at the
    // destination; a file is sent as-is so the destination becomes that file.
    if local_path.is_dir() {
        command
            .arg(format!("{}/", local_path.display()))
            .arg(format!("{REMOTE_TOKEN}:{remote_path}/"));
    } else {
        command
            .arg(local_path)
            .arg(format!("{REMOTE_TOKEN}:{remote_path}"));
    }
    finish_rsync(command, timeout).await?;
    Ok(TransferStats {
        bytes: tree_size(local_path),
    })
}

/// Whether the local system has an `rsync` binary.
async fn local_available() -> bool {
    Command::new("rsync")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Whether the remote host has an `rsync` binary.
async fn remote_available(pool: &ConnectionPool, config: &HostsConfig, host: &str) -> Result<bool> {
    let probe = pool
        .exec(
            config,
            host,
            "command -v rsync >/dev/null 2>&1 && echo yes || echo no",
            PROBE_TIMEOUT,
        )
        .await?;
    Ok(probe.stdout.trim() == "yes")
}

/// Build the base rsync command: archive-style flags, the bridge as transport,
/// and the connection chain in the environment. Callers add `--` and the paths.
fn rsync_command(chain_file: &NamedTempFile) -> Result<Command> {
    let mut command = Command::new("rsync");
    command
        // -rlptD preserves the tree without needing privilege for owners;
        // -s keeps the remote from shell-expanding the paths we pass.
        .arg("-rlptD")
        .arg("-s")
        .arg("-e")
        .arg(rsh_arg()?)
        .env(CHAIN_ENV, chain_file.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(command)
}

/// Run a prepared rsync command, bounded by `timeout`.
async fn finish_rsync(mut command: Command, timeout: Duration) -> Result<()> {
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| {
            anyhow!(
                "the rsync transfer timed out after {} seconds",
                timeout.as_secs()
            )
        })?
        .context("running rsync")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    if detail.is_empty() {
        bail!("rsync exited with a failure status");
    }
    bail!("rsync failed: {detail}");
}

/// The `-e` value pointing rsync at the bridge subcommand of this binary.
fn rsh_arg() -> Result<String> {
    let exe = std::env::current_exe().context("locating the ssh-mcp binary")?;
    let exe = exe
        .to_str()
        .context("the ssh-mcp binary path is not valid UTF-8")?;
    if exe.contains(char::is_whitespace) {
        bail!("the ssh-mcp binary path contains whitespace, which rsync's -e cannot handle");
    }
    Ok(format!("{exe} rsh-bridge"))
}

/// Resolve the host's connection chain and write it to a temporary file for
/// the bridge to read. The returned handle deletes the file when dropped.
fn write_chain(config: &HostsConfig, host: &str) -> Result<NamedTempFile> {
    let chain: Vec<Hop> = resolve_chain(config, host)?;
    let file = NamedTempFile::new().context("creating the connection chain file")?;
    let json = serde_json::to_string(&chain).context("encoding the connection chain")?;
    std::fs::write(file.path(), json).context("writing the connection chain")?;
    Ok(file)
}
