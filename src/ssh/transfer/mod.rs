//! File and directory transfer over an SSH channel, via `tar`.
//!
//! A transfer streams a gzip-compressed tar archive across one channel: a
//! download runs `tar` on the remote and extracts the stream locally; an
//! upload builds the archive locally and feeds it to a remote `tar`. `tar`
//! carries files and directories alike, and the stream is handled as raw
//! bytes throughout — never decoded as text — so binary content survives
//! intact.
//!
//! ## Layout
//!
//! The whole transfer surface is dispatched from `impl RemoteOs` below.
//! Each public method picks `posix::` or `windows::` based on the variant
//! and forwards arguments unchanged. Adding a new remote family would mean
//! adding a `RemoteOs` variant and a new sibling module, plus one extra
//! match arm per method here — no caller in `pool.rs` or `control.rs`
//! has to change.
//!
//! - `common`: OS-neutral plumbing (`run_download` / `run_upload` /
//!   `run_capture` / `run_simple` / `check_remote`, tar pack and unpack,
//!   `exec_capture` for sync gates that build their own walk command).
//! - `posix`: POSIX `tar` / `find` / `rm` / `mkdir` / `test -d`.
//! - `windows`: PowerShell + `tar.exe` + `Test-Path` / `Remove-Item`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use russh::{Channel, client};

use super::pool::RemoteOs;

mod common;
mod posix;
mod windows;

pub use common::{TransferStats, exec_capture};

// Several of these dispatch methods naturally carry 7-8 parameters: each
// forwards the channel, the source/dest pair, an exclude list, a timeout,
// and the connection's encoding to its underlying implementation. The
// alternative — grouping into a struct just to fit clippy's 7-argument
// limit — would obscure the call sites without removing any state, so the
// limit is silenced for the whole impl block.
#[allow(clippy::too_many_arguments)]
impl RemoteOs {
    /// Download a remote file or directory to `local_path`. `cp` semantics
    /// on the destination: existing directory = land inside, otherwise
    /// replace.
    pub async fn download(
        self,
        channel: Channel<client::Msg>,
        remote_path: &str,
        local_path: &Path,
        exclude: &[String],
        timeout: Duration,
        encoding: &'static encoding_rs::Encoding,
    ) -> Result<TransferStats> {
        match self {
            RemoteOs::Posix => {
                posix::download(channel, remote_path, local_path, exclude, timeout, encoding).await
            }
            RemoteOs::Windows => {
                windows::download(channel, remote_path, local_path, exclude, timeout, encoding)
                    .await
            }
        }
    }

    /// Upload a local file or directory to `remote_path`. `cp` semantics
    /// on the destination: existing directory = land inside, otherwise
    /// replace. The caller probes `remote_is_dir` first and passes the
    /// answer as `remote_is_existing_dir`.
    pub async fn upload(
        self,
        channel: Channel<client::Msg>,
        local_path: &Path,
        remote_path: &str,
        remote_is_existing_dir: bool,
        exclude: &[String],
        timeout: Duration,
        encoding: &'static encoding_rs::Encoding,
    ) -> Result<TransferStats> {
        match self {
            RemoteOs::Posix => {
                posix::upload(
                    channel,
                    local_path,
                    remote_path,
                    remote_is_existing_dir,
                    exclude,
                    timeout,
                    encoding,
                )
                .await
            }
            RemoteOs::Windows => {
                windows::upload(
                    channel,
                    local_path,
                    remote_path,
                    remote_is_existing_dir,
                    exclude,
                    timeout,
                    encoding,
                )
                .await
            }
        }
    }

    /// Pack a chosen subset of files under `source_root` into a tar archive
    /// and stream it into `target_dir` on the remote. The archive entry
    /// names equal the supplied relative paths, so on extraction they land
    /// at `<target_dir>/<rel>`.
    pub async fn upload_entries(
        self,
        channel: Channel<client::Msg>,
        source_root: &Path,
        source_root_name: &Path,
        rel_paths: &[PathBuf],
        target_dir: &str,
        timeout: Duration,
        encoding: &'static encoding_rs::Encoding,
    ) -> Result<u64> {
        match self {
            RemoteOs::Posix => {
                posix::upload_entries(
                    channel,
                    source_root,
                    source_root_name,
                    rel_paths,
                    target_dir,
                    timeout,
                    encoding,
                )
                .await
            }
            RemoteOs::Windows => {
                windows::upload_entries(
                    channel,
                    source_root,
                    source_root_name,
                    rel_paths,
                    target_dir,
                    timeout,
                    encoding,
                )
                .await
            }
        }
    }

    /// Ask the remote to tar a chosen subset of files under `source_root`,
    /// stream it back, and extract the archive into `dest_root` locally.
    pub async fn download_entries(
        self,
        channel: Channel<client::Msg>,
        source_root: &str,
        rel_paths_inside_source: &[PathBuf],
        dest_root: &Path,
        timeout: Duration,
        encoding: &'static encoding_rs::Encoding,
    ) -> Result<u64> {
        match self {
            RemoteOs::Posix => {
                posix::download_entries(
                    channel,
                    source_root,
                    rel_paths_inside_source,
                    dest_root,
                    timeout,
                    encoding,
                )
                .await
            }
            RemoteOs::Windows => {
                windows::download_entries(
                    channel,
                    source_root,
                    rel_paths_inside_source,
                    dest_root,
                    timeout,
                    encoding,
                )
                .await
            }
        }
    }

    /// Remove a list of relative paths under `root` on the remote. Used by
    /// `sync_*` to apply the change set's `Delete` entries.
    pub async fn delete_remote(
        self,
        channel: Channel<client::Msg>,
        root: &str,
        rel_paths: &[PathBuf],
        timeout: Duration,
        encoding: &'static encoding_rs::Encoding,
    ) -> Result<()> {
        match self {
            RemoteOs::Posix => {
                posix::delete_remote(channel, root, rel_paths, timeout, encoding).await
            }
            RemoteOs::Windows => {
                windows::delete_remote(channel, root, rel_paths, timeout, encoding).await
            }
        }
    }

    /// Detect whether a remote path is an existing directory. A non-zero
    /// exit (or any error from the test command) is reported as `false`,
    /// covering both "does not exist" and "exists but is a file / symlink".
    pub async fn remote_is_dir(self, channel: Channel<client::Msg>, path: &str) -> Result<bool> {
        match self {
            RemoteOs::Posix => posix::remote_is_dir(channel, path).await,
            RemoteOs::Windows => windows::remote_is_dir(channel, path).await,
        }
    }
}
