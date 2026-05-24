//! The SSH connection pool and command execution.
//!
//! One russh connection per host is kept and reused across `exec` calls;
//! channels are opened per command. Execution is stateless — no cwd or shell
//! state carries between commands — so a reconnect restores nothing and is
//! transparent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::{Channel, ChannelMsg, client};
use tokio::sync::Mutex;

use super::connect::{CONNECT_TIMEOUT, SshConnector, resolve_chain};
use super::handler::StrictHostKey;
use super::transfer::{self, TransferStats};
use crate::changeset::{self, ChangeOp};
use crate::config::HostsConfig;

/// How long to wait for a session channel to open before treating the pooled
/// connection as dead — a healthy connection opens one in a single round trip.
const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// The result of a `sync_*` call: bytes that crossed the wire plus the
/// change set itself, so the caller can summarize counts and record each
/// per-file decision in the trace buffer.
pub struct SyncResult {
    pub bytes: u64,
    pub change_set: crate::changeset::ChangeSet,
}

/// Which output stream a remote-command chunk belongs to. Used to preserve
/// the arrival order across stdout and stderr so the trace buffer can
/// reconstruct line-level interleaving — the natural reading order of
/// progress lines and the warnings that landed between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputChannel {
    Stdout,
    Stderr,
}

/// What kind of shell the remote runs commands under. Probed once per
/// connection (right after the handshake) and cached for the connection's
/// lifetime — `uname -s` then `ver` as a fallback resolves which it is.
///
/// The distinction only matters to file transfer: an exec call runs whatever
/// command the caller wrote in whatever shell the remote provides, but the
/// transfer engine has to construct shell commands itself (find, sha256sum,
/// tar, rm) and those differ between POSIX and Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteOs {
    /// Any Unix-like host (Linux, macOS, *BSD, ...). The transfer engine
    /// assumes `find`, `sha256sum` or `shasum -a 256`, `tar`, `rm -rf`,
    /// `mkdir -p`.
    Posix,
    /// Windows host running OpenSSH server (commands run under cmd.exe by
    /// default). The transfer engine has its own command shapes built on
    /// PowerShell, `tar.exe` (libarchive, shipped with Windows 10 1803+),
    /// and `Get-FileHash`.
    Windows,
}

/// A pooled SSH connection together with the probed OS of the remote and
/// the encoding the remote's console emits text bytes in. The encoding is
/// always UTF-8 for POSIX (where shells are typically locale-correct and
/// most distros are UTF-8 by default); for Windows it is whatever
/// `chcp` reports at connect time (CP932 on Japanese installs, CP437 on
/// US-English, etc). Stored as a `&'static Encoding` because every
/// `encoding_rs::Encoding` value is a `'static` singleton.
#[derive(Clone)]
pub struct PooledConnection {
    pub handle: Arc<client::Handle<StrictHostKey>>,
    pub os: RemoteOs,
    pub encoding: &'static encoding_rs::Encoding,
}

/// The result of running one remote command.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    /// Raw byte chunks in the order they arrived from the remote, tagged by
    /// their stream. Splitting these into lines and emitting whichever side
    /// completed a line first reproduces the temporal interleaving the user
    /// would have seen on a real terminal.
    pub chunks: Vec<(OutputChannel, Vec<u8>)>,
    /// The remote exit code, or `-1` if the command was signalled or the
    /// channel closed without reporting one.
    pub exit_code: i32,
}

/// A pool of live SSH connections, keyed by host alias.
pub struct ConnectionPool {
    connections: Mutex<HashMap<String, PooledConnection>>,
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
        // The command goes to the remote verbatim — we do *not* try to
        // rewrite shell quoting or force a code page on the remote. The
        // pooled connection already knows what encoding to interpret the
        // returned bytes with (UTF-8 for POSIX, whatever `chcp` reported
        // for Windows), so handling stays on the daemon side and the
        // caller can write the most natural shell command for the host.
        let pc = self.get_or_connect(config, host_alias).await?;
        let mut channel = self.open_session(config, host_alias).await?;
        run_command(&mut channel, command, timeout, pc.encoding).await
    }

    /// Download a remote file or directory to `local_path`.
    ///
    /// The destination follows `cp` semantics: if `local_path` is an existing
    /// directory the downloaded entry is placed inside it under its remote
    /// base name; otherwise the downloaded entry replaces `local_path`.
    /// Entries matching an `exclude` glob are skipped.
    pub async fn get_file(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        remote_path: &str,
        local_path: &Path,
        exclude: &[String],
        timeout: Duration,
    ) -> Result<TransferStats> {
        let pc = self.get_or_connect(config, host_alias).await?;
        let channel = self.open_session(config, host_alias).await?;
        pc.os
            .download(
                channel,
                remote_path,
                local_path,
                exclude,
                timeout,
                pc.encoding,
            )
            .await
    }

    /// Synchronise a local directory into a remote location, mirroring it:
    /// files present on the remote but not on the local source are deleted.
    /// Returns the change set so the caller can record per-entry detail and
    /// the byte count of the archive payload.
    pub async fn sync_put(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        local_path: &Path,
        remote_path: &str,
        exclude: &[String],
        timeout: Duration,
    ) -> Result<SyncResult> {
        let pc = self.get_or_connect(config, host_alias).await?;
        if !local_path.is_dir() {
            bail!(
                "sync_put requires the local source to be a directory; {} is not",
                local_path.display()
            );
        }
        // sync_* treats `remote_path` as a stable destination root, not as a
        // cp-merge target — that is what mirror semantics want (the same
        // mapping every run). The remote root is created on demand by the
        // upload step's `mkdir -p` (POSIX) or `mkdir` (Windows).
        let empty = PathBuf::new();
        let (name_only, _complex) = changeset::partition_excludes(exclude);
        let local_excludes = changeset::compile_excludes(exclude)?;
        let source_map = changeset::walk_local(local_path, &empty, &local_excludes)?;

        let walk_channel = self.open_session(config, host_alias).await?;
        let walk_cmd = pc.os.walk_command_with_hashes(remote_path, &name_only);
        let walk_out =
            transfer::exec_capture(walk_channel, &walk_cmd, timeout, pc.encoding).await?;
        let dest_map = changeset::parse_walk_output(&walk_out, &empty)?;

        let change_set = changeset::compute(source_map, dest_map, true);
        let outgoing: Vec<PathBuf> = change_set.outgoing().map(|e| e.rel_path.clone()).collect();
        let deletes: Vec<PathBuf> = change_set
            .entries
            .iter()
            .filter(|e| e.op == ChangeOp::Delete)
            .map(|e| e.rel_path.clone())
            .collect();

        let mut bytes = 0u64;
        if !outgoing.is_empty() {
            let channel = self.open_session(config, host_alias).await?;
            bytes = pc
                .os
                .upload_entries(
                    channel,
                    local_path,
                    &empty,
                    &outgoing,
                    remote_path,
                    timeout,
                    pc.encoding,
                )
                .await?;
        }
        if !deletes.is_empty() {
            let channel = self.open_session(config, host_alias).await?;
            pc.os
                .delete_remote(channel, remote_path, &deletes, timeout, pc.encoding)
                .await?;
        }
        Ok(SyncResult { bytes, change_set })
    }

    /// Synchronise a remote directory into a local location, mirroring it.
    pub async fn sync_get(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        remote_path: &str,
        local_path: &Path,
        exclude: &[String],
        timeout: Duration,
    ) -> Result<SyncResult> {
        let pc = self.get_or_connect(config, host_alias).await?;
        let probe = self.open_session(config, host_alias).await?;
        let remote_is_dir = pc.os.remote_is_dir(probe, remote_path).await?;
        if !remote_is_dir {
            bail!("sync_get requires the remote source to be a directory; {remote_path:?} is not");
        }
        let empty = PathBuf::new();
        let (name_only, _complex) = changeset::partition_excludes(exclude);
        let walk_channel = self.open_session(config, host_alias).await?;
        let walk_cmd = pc.os.walk_command_with_hashes(remote_path, &name_only);
        let walk_out =
            transfer::exec_capture(walk_channel, &walk_cmd, timeout, pc.encoding).await?;
        let source_map = changeset::parse_walk_output(&walk_out, &empty)?;

        let local_excludes = changeset::compile_excludes(exclude)?;
        let dest_map = changeset::walk_local(local_path, &empty, &local_excludes)?;

        let change_set = changeset::compute(source_map, dest_map, true);
        let outgoing: Vec<PathBuf> = change_set.outgoing().map(|e| e.rel_path.clone()).collect();
        let deletes: Vec<PathBuf> = change_set
            .entries
            .iter()
            .filter(|e| e.op == ChangeOp::Delete)
            .map(|e| e.rel_path.clone())
            .collect();

        let mut bytes = 0u64;
        if !outgoing.is_empty() {
            std::fs::create_dir_all(local_path)
                .with_context(|| format!("creating {}", local_path.display()))?;
            let channel = self.open_session(config, host_alias).await?;
            bytes = pc
                .os
                .download_entries(
                    channel,
                    remote_path,
                    &outgoing,
                    local_path,
                    timeout,
                    pc.encoding,
                )
                .await?;
        }
        for rel in &deletes {
            let target = local_path.join(rel);
            if let Ok(meta) = target.symlink_metadata() {
                if meta.is_dir() {
                    let _ = std::fs::remove_dir_all(&target);
                } else {
                    let _ = std::fs::remove_file(&target);
                }
            }
        }
        Ok(SyncResult { bytes, change_set })
    }

    /// Upload a local file or directory to `remote_path`.
    ///
    /// The destination follows `cp` semantics: if `remote_path` is an existing
    /// directory the local entry is placed inside it under its local base
    /// name; otherwise the local entry replaces whatever is at `remote_path`.
    /// Entries matching an `exclude` glob are skipped.
    pub async fn put_file(
        &self,
        config: &HostsConfig,
        host_alias: &str,
        local_path: &Path,
        remote_path: &str,
        exclude: &[String],
        timeout: Duration,
    ) -> Result<TransferStats> {
        let pc = self.get_or_connect(config, host_alias).await?;
        // The destination resolution depends on whether `remote_path` is an
        // existing directory, which only the remote can tell us. The probe
        // and the transfer each get their own channel — channels are
        // single-use under russh, and the connection is pooled so there is no
        // round-trip for the second open.
        let probe = self.open_session(config, host_alias).await?;
        let remote_is_dir = pc.os.remote_is_dir(probe, remote_path).await?;
        let channel = self.open_session(config, host_alias).await?;
        pc.os
            .upload(
                channel,
                local_path,
                remote_path,
                remote_is_dir,
                exclude,
                timeout,
                pc.encoding,
            )
            .await
    }

    /// Open a fresh channel on a host's pooled connection. A dead pooled
    /// connection is detected when the channel fails to open or times out, and
    /// is replaced once before retrying.
    async fn open_session(
        &self,
        config: &HostsConfig,
        host_alias: &str,
    ) -> Result<Channel<client::Msg>> {
        let pc = self.get_or_connect(config, host_alias).await?;
        match open_channel(&pc.handle).await {
            Ok(channel) => Ok(channel),
            Err(_) => {
                // The pooled connection looks dead; drop it and reconnect once.
                self.evict(host_alias).await;
                let pc = self.get_or_connect(config, host_alias).await?;
                open_channel(&pc.handle)
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
    ) -> Result<PooledConnection> {
        {
            let connections = self.connections.lock().await;
            if let Some(pc) = connections.get(host_alias) {
                return Ok(pc.clone());
            }
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
        // Probe the remote's shell family before sharing the connection.
        // A concurrent caller racing on the same host can probe a second
        // time; the eventual cached value is the same and the cost is small
        // enough not to justify a per-host probe lock.
        let os = probe_remote_os(&handle).await;
        let encoding = match os {
            RemoteOs::Posix => encoding_rs::UTF_8,
            RemoteOs::Windows => probe_windows_encoding(&handle).await,
        };
        let pc = PooledConnection {
            handle,
            os,
            encoding,
        };
        let mut connections = self.connections.lock().await;
        connections
            .entry(host_alias.to_string())
            .or_insert_with(|| pc.clone());
        Ok(pc)
    }

    /// The probed OS of a host's pooled connection, opening one if needed.
    /// Internal callers (transfer / sync) use this to branch on `Windows`
    /// vs `Posix` shell-command shapes; missing-host or connect-error cases
    /// surface as a regular error.
    pub async fn remote_os(&self, config: &HostsConfig, host_alias: &str) -> Result<RemoteOs> {
        Ok(self.get_or_connect(config, host_alias).await?.os)
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
    encoding: &'static encoding_rs::Encoding,
) -> Result<ExecOutput> {
    match tokio::time::timeout(timeout, collect_output(channel, command, encoding)).await {
        Ok(result) => result,
        Err(_) => {
            let _ = channel.close().await;
            bail!("command timed out after {} seconds", timeout.as_secs())
        }
    }
}

async fn collect_output(
    channel: &mut Channel<client::Msg>,
    command: &str,
    encoding: &'static encoding_rs::Encoding,
) -> Result<ExecOutput> {
    channel
        .exec(true, command)
        .await
        .context("the remote exec request failed")?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut chunks: Vec<(OutputChannel, Vec<u8>)> = Vec::new();
    let mut exit_code = -1;

    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                stdout.extend_from_slice(&data);
                chunks.push((OutputChannel::Stdout, data.to_vec()));
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                stderr.extend_from_slice(&data);
                chunks.push((OutputChannel::Stderr, data.to_vec()));
            }
            ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
            _ => {}
        }
    }

    // Decode the collected bytes using the connection's known encoding.
    // `encoding_rs::Encoding::decode` lossily replaces invalid sequences
    // with U+FFFD, matching the previous `from_utf8_lossy` behaviour for
    // truly garbled bytes while correctly transcoding well-formed text
    // (e.g. CP932 Japanese error messages from PowerShell on Windows).
    let (stdout_text, _, _) = encoding.decode(&stdout);
    let (stderr_text, _, _) = encoding.decode(&stderr);
    Ok(ExecOutput {
        stdout: stdout_text.into_owned(),
        stderr: stderr_text.into_owned(),
        chunks,
        exit_code,
    })
}

/// How long to wait for the OS probe to settle. Generous so that a slow
/// remote on first connect doesn't get mislabelled; short enough that a
/// genuinely broken host doesn't hold up the rest of the daemon.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Probe the remote's shell family. Best-effort: any failure resolves to
/// `Posix` because that is the dominant case and the wrong guess only
/// changes which clean error the user gets for a file transfer.
///
/// The probe runs two short commands at most. On POSIX, `uname -s` exits 0
/// with `Linux` / `Darwin` / etc. — done. On Windows the same command is
/// unknown to cmd.exe (errorlevel 9009 and a mojibake "not recognized"
/// message), so the second probe tries `ver`, which prints
/// `Microsoft Windows [Version ...]` from cmd.exe and nothing useful from
/// a POSIX shell.
async fn probe_remote_os(handle: &client::Handle<StrictHostKey>) -> RemoteOs {
    if let Some(out) = probe_one(handle, "uname -s").await {
        let trimmed = out.stdout.trim();
        if out.exit_code == 0 && !trimmed.is_empty() {
            return RemoteOs::Posix;
        }
    }
    // `ver` is a cmd.exe builtin and is *not* recognised by PowerShell (the
    // default shell on most Windows OpenSSH setups), so probing for `ver`
    // directly false-negatives on PS-default hosts. Going through `cmd /c`
    // forces cmd.exe to evaluate `ver`, which works whether the login shell
    // is cmd or PowerShell, while still failing cleanly on POSIX (where
    // `cmd` is just an unknown command).
    if let Some(out) = probe_one(handle, "cmd /c ver").await
        && out.stdout.contains("Microsoft Windows")
    {
        return RemoteOs::Windows;
    }
    // Default: assume POSIX. If we got here something unusual is happening
    // (probe channel failed, weird shell, ...) but POSIX is the more
    // permissive guess — transfer code will still error cleanly if the
    // tar/find/sha256sum it tries to run isn't there.
    RemoteOs::Posix
}

/// Run a single probe command and collect its short result, returning
/// `None` for any kind of channel-level failure (so the caller falls
/// through to the next probe attempt without erroring out the whole
/// connection).
async fn probe_one(handle: &client::Handle<StrictHostKey>, command: &str) -> Option<ExecOutput> {
    let mut channel = open_channel(handle).await.ok()?;
    // Probes look at ASCII-only fields (`Linux\n`, `Microsoft Windows`,
    // `Active code page: 932`) so UTF-8 is a safe decoding choice even
    // before we know the remote's real encoding.
    tokio::time::timeout(
        PROBE_TIMEOUT,
        collect_output(&mut channel, command, encoding_rs::UTF_8),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
}

/// Probe the Windows console code page once at connect time by running
/// `cmd /c chcp`. The output line ends with the active code page in
/// ASCII digits, regardless of UI locale (e.g. `Active code page: 437`
/// in English, `現在のコード ページ: 932` in Japanese — the trailing
/// integer is the same place either way). Maps to an `encoding_rs`
/// encoding; falls back to UTF-8 if the probe fails or the code page is
/// one we don't have a mapping for, which gives the same lossy decoding
/// we used before this feature existed.
async fn probe_windows_encoding(
    handle: &client::Handle<StrictHostKey>,
) -> &'static encoding_rs::Encoding {
    let Some(out) = probe_one(handle, "cmd /c chcp").await else {
        return encoding_rs::UTF_8;
    };
    let cp = out
        .stdout
        .split_whitespace()
        .filter_map(|tok| tok.parse::<u32>().ok())
        .next_back();
    match cp {
        Some(cp) => windows_codepage_to_encoding(cp),
        None => encoding_rs::UTF_8,
    }
}

/// Map a Windows console code page number to the closest `encoding_rs`
/// encoding. Only the common ones are listed — anything unrecognised
/// degrades to UTF-8 (the previous behaviour, which is lossy on non-
/// UTF-8 bytes but the safest default for hosts we have no information
/// about).
fn windows_codepage_to_encoding(cp: u32) -> &'static encoding_rs::Encoding {
    match cp {
        65001 => encoding_rs::UTF_8,
        932 => encoding_rs::SHIFT_JIS,
        936 => encoding_rs::GBK,
        949 => encoding_rs::EUC_KR,
        950 => encoding_rs::BIG5,
        1250 => encoding_rs::WINDOWS_1250,
        1251 => encoding_rs::WINDOWS_1251,
        1252 => encoding_rs::WINDOWS_1252,
        1253 => encoding_rs::WINDOWS_1253,
        1254 => encoding_rs::WINDOWS_1254,
        1255 => encoding_rs::WINDOWS_1255,
        1256 => encoding_rs::WINDOWS_1256,
        1257 => encoding_rs::WINDOWS_1257,
        1258 => encoding_rs::WINDOWS_1258,
        _ => encoding_rs::UTF_8,
    }
}
