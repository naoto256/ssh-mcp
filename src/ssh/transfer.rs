//! File and directory transfer over an SSH channel, via `tar`.
//!
//! A transfer streams a gzip-compressed tar archive across one channel: a
//! download runs `tar` on the remote and extracts the stream locally; an
//! upload builds the archive locally and feeds it to a remote `tar`. `tar`
//! carries files and directories alike, and the stream is handled as raw
//! bytes throughout — never decoded as text — so binary content survives
//! intact.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use globset::{Glob, GlobSet, GlobSetBuilder};
use russh::{Channel, ChannelMsg, client};
use tar::{Archive, Builder};
use tempfile::NamedTempFile;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Statistics from one completed transfer.
#[derive(Debug, Clone)]
pub struct TransferStats {
    /// The size of the compressed archive that crossed the connection, in bytes.
    pub bytes: u64,
}

/// The outcome of the remote `tar` process.
struct RemoteResult {
    exit_code: i32,
    stderr: String,
}

/// Download a remote file or directory to `local_path`.
///
/// The destination follows `cp` semantics: if `local_path` is an existing
/// directory the downloaded entry is placed inside it under its remote base
/// name; otherwise the downloaded entry replaces `local_path`. An entry whose
/// name matches an `exclude` glob is left out of the archive.
pub async fn download(
    mut channel: Channel<client::Msg>,
    remote_path: &str,
    local_path: &Path,
    exclude: &[String],
    timeout: Duration,
) -> Result<TransferStats> {
    let (dir, base) = split_remote(remote_path)?;
    let target = resolve_download_target(local_path, &base);
    let parent = local_parent(&target);
    if !parent.is_dir() {
        bail!("the local directory {} does not exist", parent.display());
    }

    // `tar -C dir base` archives `base` relative to `dir`, so the archive's top
    // entry is exactly `base` regardless of how deep the remote path was. `-z`
    // gzips the stream on the remote; each `--exclude` drops a matching name.
    let mut command = format!("tar -cz -f - -C {}", shell_quote(&dir));
    for pattern in exclude {
        command.push_str(&format!(" --exclude={}", shell_quote(pattern)));
    }
    command.push_str(&format!(" -- {}", shell_quote(&base)));

    let tar_file = NamedTempFile::new().context("creating a temporary archive file")?;
    let mut sink =
        tokio::fs::File::from_std(tar_file.reopen().context("opening the temporary archive")?);

    let (result, bytes) =
        tokio::time::timeout(timeout, run_download(&mut channel, &command, &mut sink))
            .await
            .map_err(|_| anyhow!("the transfer timed out after {} seconds", timeout.as_secs()))??;
    check_remote(&result)?;

    let archive = tar_file.path().to_path_buf();
    let dest = target;
    let entry = base.clone();
    tokio::task::spawn_blocking(move || unpack(&archive, &entry, &dest))
        .await
        .context("the archive extraction task failed")??;
    Ok(TransferStats { bytes })
}

/// Resolve where a downloaded entry should land. `cp` semantics: if the
/// caller-supplied destination is already a directory, the entry is placed
/// inside it under its remote base name; otherwise the destination is taken
/// as-is and replaces whatever was there.
fn resolve_download_target(dest: &Path, entry_name: &str) -> PathBuf {
    if dest.is_dir() {
        dest.join(entry_name)
    } else {
        dest.to_path_buf()
    }
}

/// Upload a local file or directory to `remote_path` by streaming a tar archive
/// over `channel`. The caller must report whether `remote_path` already exists
/// as a directory: when it does, `cp` semantics place the local entry inside
/// it under its local base name; otherwise the local entry replaces whatever
/// is at `remote_path`. The remote parent directory is created if it is
/// missing. An entry whose name matches an `exclude` glob is left out.
pub async fn upload(
    mut channel: Channel<client::Msg>,
    local_path: &Path,
    remote_path: &str,
    remote_is_existing_dir: bool,
    exclude: &[String],
    timeout: Duration,
) -> Result<TransferStats> {
    if !local_path.exists() {
        bail!("the local path {} does not exist", local_path.display());
    }
    let excludes = compile_excludes(exclude)?;

    let (dir, base) = resolve_upload_target(local_path, remote_path, remote_is_existing_dir)?;
    let tar_file = NamedTempFile::new().context("creating a temporary archive file")?;
    let archive = tar_file.path().to_path_buf();
    let source = local_path.to_path_buf();
    let entry = base.clone();
    tokio::task::spawn_blocking(move || pack(&source, &entry, &archive, &excludes))
        .await
        .context("the archive creation task failed")??;
    let bytes = tar_file
        .as_file()
        .metadata()
        .context("sizing the archive")?
        .len();

    let command = format!(
        "mkdir -p -- {dir} && tar -xz -f - -C {dir}",
        dir = shell_quote(&dir)
    );
    let input =
        tokio::fs::File::from_std(tar_file.reopen().context("opening the temporary archive")?);

    let result = tokio::time::timeout(timeout, run_upload(&mut channel, &command, input))
        .await
        .map_err(|_| anyhow!("the transfer timed out after {} seconds", timeout.as_secs()))??;
    check_remote(&result)?;
    Ok(TransferStats { bytes })
}

/// Resolve where an uploaded archive should land. `cp` semantics: if
/// `remote_path` exists as a directory the local entry is placed inside it
/// under its local base name; otherwise the local entry replaces whatever is
/// at `remote_path` (its name is taken from `remote_path`'s tail).
fn resolve_upload_target(
    local_path: &Path,
    remote_path: &str,
    remote_is_existing_dir: bool,
) -> Result<(String, String)> {
    if remote_is_existing_dir {
        let local_base = local_path
            .file_name()
            .ok_or_else(|| anyhow!("the local path {} has no file name", local_path.display()))?
            .to_string_lossy()
            .into_owned();
        let dir = remote_path.trim_end_matches('/');
        let dir = if dir.is_empty() { "/" } else { dir };
        Ok((dir.to_string(), local_base))
    } else {
        split_remote(remote_path)
    }
}

/// Pack a chosen subset of files under `source_root` into a tar archive and
/// stream it into `target_dir` on the remote. The archive entry names equal
/// the supplied relative paths (e.g. `proj/src/foo.rs`), so on extraction
/// they land at `<target_dir>/<rel>`. Returns the archive byte count.
pub async fn upload_entries(
    mut channel: Channel<client::Msg>,
    source_root: &Path,
    source_root_name: &Path,
    rel_paths: &[PathBuf],
    target_dir: &str,
    timeout: Duration,
) -> Result<u64> {
    let tar_file = NamedTempFile::new().context("creating a temporary archive file")?;
    let archive = tar_file.path().to_path_buf();
    let root = source_root.to_path_buf();
    let base = source_root_name.to_path_buf();
    let paths = rel_paths.to_vec();
    tokio::task::spawn_blocking(move || pack_entries(&root, &base, &paths, &archive))
        .await
        .context("the archive creation task failed")??;
    let bytes = tar_file
        .as_file()
        .metadata()
        .context("sizing the archive")?
        .len();

    let command = format!(
        "mkdir -p -- {dir} && tar -xz -f - -C {dir}",
        dir = shell_quote(target_dir)
    );
    let input =
        tokio::fs::File::from_std(tar_file.reopen().context("opening the temporary archive")?);
    let result = tokio::time::timeout(timeout, run_upload(&mut channel, &command, input))
        .await
        .map_err(|_| anyhow!("the transfer timed out after {} seconds", timeout.as_secs()))??;
    check_remote(&result)?;
    Ok(bytes)
}

/// Synchronous counterpart of `upload_entries`'s pack step.
fn pack_entries(
    source_root: &Path,
    source_root_name: &Path,
    rel_paths: &[PathBuf],
    archive: &Path,
) -> Result<()> {
    let file = std::fs::File::create(archive)
        .with_context(|| format!("creating {}", archive.display()))?;
    let mut builder = Builder::new(GzEncoder::new(file, Compression::default()));
    builder.follow_symlinks(false);
    let meta = std::fs::symlink_metadata(source_root)
        .with_context(|| format!("reading {}", source_root.display()))?;
    for rel in rel_paths {
        // For a single-file source the relative path is just `<basename>`,
        // so the local file path is `source_root` itself; for a directory
        // source it is `source_root + rel_inside_root`.
        let local = if meta.is_file() {
            source_root.to_path_buf()
        } else {
            let inside = rel.strip_prefix(source_root_name).unwrap_or(rel);
            source_root.join(inside)
        };
        builder
            .append_path_with_name(&local, rel)
            .with_context(|| format!("archiving {}", local.display()))?;
    }
    builder
        .into_inner()
        .context("finalising the archive")?
        .finish()
        .context("finalising the gzip stream")?;
    Ok(())
}

/// Ask the remote to tar a chosen subset of files under `source_root`,
/// stream it back, and extract the archive into `dest_root` locally
/// (creating `dest_root` if it does not yet exist). Returns the compressed
/// archive byte count.
pub async fn download_entries(
    mut channel: Channel<client::Msg>,
    source_root: &str,
    rel_paths_inside_source: &[PathBuf],
    dest_root: &Path,
    timeout: Duration,
) -> Result<u64> {
    std::fs::create_dir_all(dest_root)
        .with_context(|| format!("creating {}", dest_root.display()))?;
    let mut command = format!("tar -cz -f - -C {}", shell_quote(source_root));
    command.push_str(" --");
    for rel in rel_paths_inside_source {
        command.push(' ');
        command.push_str(&shell_quote(&rel.to_string_lossy()));
    }

    let tar_file = NamedTempFile::new().context("creating a temporary archive file")?;
    let mut sink =
        tokio::fs::File::from_std(tar_file.reopen().context("opening the temporary archive")?);

    let (result, bytes) =
        tokio::time::timeout(timeout, run_download(&mut channel, &command, &mut sink))
            .await
            .map_err(|_| anyhow!("the transfer timed out after {} seconds", timeout.as_secs()))??;
    check_remote(&result)?;

    let archive = tar_file.path().to_path_buf();
    let dest = dest_root.to_path_buf();
    tokio::task::spawn_blocking(move || unpack_into(&archive, &dest))
        .await
        .context("the archive extraction task failed")??;
    Ok(bytes)
}

/// Extract an archive's contents straight into `dest_dir`, merging into
/// whatever already lives there. Files inside the archive are overwritten if
/// they collide with existing ones; files outside the archive are left
/// alone.
fn unpack_into(archive: &Path, dest_dir: &Path) -> Result<()> {
    let file = std::fs::File::open(archive).context("opening the downloaded archive")?;
    let mut archive = Archive::new(GzDecoder::new(file));
    // The default behaviour overwrites existing files; we want that.
    archive
        .unpack(dest_dir)
        .context("extracting the downloaded archive")?;
    Ok(())
}

/// Capture stdout from a one-shot remote command, returning it as a single
/// string. Errors carry the remote stderr.
pub async fn exec_capture(
    mut channel: Channel<client::Msg>,
    command: &str,
    timeout: Duration,
) -> Result<String> {
    let mut stdout = Vec::new();
    let mut sink = std::io::Cursor::new(&mut stdout);
    let (result, _bytes) =
        tokio::time::timeout(timeout, run_capture(&mut channel, command, &mut sink))
            .await
            .map_err(|_| {
                anyhow!(
                    "the remote command timed out after {} seconds",
                    timeout.as_secs()
                )
            })??;
    check_remote(&result)?;
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Synchronous-sink variant of `run_download` for in-memory capture.
async fn run_capture(
    channel: &mut Channel<client::Msg>,
    command: &str,
    sink: &mut std::io::Cursor<&mut Vec<u8>>,
) -> Result<(RemoteResult, u64)> {
    channel
        .exec(true, command)
        .await
        .context("the remote command request failed")?;
    let mut stderr = Vec::new();
    let mut exit_code = -1;
    let mut bytes = 0u64;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                std::io::Write::write_all(sink, &data).context("capturing remote stdout")?;
                bytes += data.len() as u64;
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
            _ => {}
        }
    }
    Ok((
        RemoteResult {
            exit_code,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        },
        bytes,
    ))
}

/// Remove a list of relative paths under `root` on the remote with
/// `rm -rf`. Used by `sync_*` to apply the change set's `Delete` entries.
pub async fn delete_remote(
    mut channel: Channel<client::Msg>,
    root: &str,
    rel_paths: &[PathBuf],
    timeout: Duration,
) -> Result<()> {
    if rel_paths.is_empty() {
        return Ok(());
    }
    let mut command = format!("cd {} && rm -rf --", shell_quote(root));
    for rel in rel_paths {
        command.push(' ');
        command.push_str(&shell_quote(&rel.to_string_lossy()));
    }
    let result = tokio::time::timeout(timeout, run_simple(&mut channel, &command))
        .await
        .map_err(|_| {
            anyhow!(
                "the remote rm timed out after {} seconds",
                timeout.as_secs()
            )
        })??;
    check_remote(&result)?;
    Ok(())
}

/// Run a command that produces no output we care about, returning its exit
/// status and stderr.
async fn run_simple(channel: &mut Channel<client::Msg>, command: &str) -> Result<RemoteResult> {
    channel
        .exec(true, command)
        .await
        .context("the remote command request failed")?;
    let mut stderr = Vec::new();
    let mut exit_code = -1;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
            _ => {}
        }
    }
    Ok(RemoteResult {
        exit_code,
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// Detect whether a remote path is an existing directory by running a short
/// `test -d` over `channel`. A non-zero exit is taken to mean "not a directory"
/// — this covers both "does not exist" and "exists but is a file or symlink",
/// which take the same `cp` branch (the local entry replaces the path).
pub async fn remote_is_dir(mut channel: Channel<client::Msg>, path: &str) -> Result<bool> {
    let command = format!("test -d {}", shell_quote(path));
    channel
        .exec(true, command)
        .await
        .context("the remote test request failed")?;
    let mut exit_code = -1;
    while let Some(message) = channel.wait().await {
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit_code = exit_status as i32;
        }
    }
    Ok(exit_code == 0)
}

/// Run the remote archive command and stream its stdout to `sink`, returning
/// the remote result and the number of bytes written.
async fn run_download<W: AsyncWrite + Unpin>(
    channel: &mut Channel<client::Msg>,
    command: &str,
    sink: &mut W,
) -> Result<(RemoteResult, u64)> {
    channel
        .exec(true, command)
        .await
        .context("the remote tar request failed")?;

    let mut stderr = Vec::new();
    let mut exit_code = -1;
    let mut bytes = 0u64;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                sink.write_all(&data)
                    .await
                    .context("writing the downloaded archive")?;
                bytes += data.len() as u64;
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
            _ => {}
        }
    }
    sink.flush()
        .await
        .context("flushing the downloaded archive")?;
    Ok((
        RemoteResult {
            exit_code,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        },
        bytes,
    ))
}

/// Run the remote extract command and stream `input` into its stdin.
async fn run_upload<R: AsyncRead + Unpin>(
    channel: &mut Channel<client::Msg>,
    command: &str,
    input: R,
) -> Result<RemoteResult> {
    channel
        .exec(true, command)
        .await
        .context("the remote tar request failed")?;
    channel
        .data(input)
        .await
        .context("streaming the archive to the remote")?;
    channel
        .eof()
        .await
        .context("signalling the end of the archive")?;

    let mut stderr = Vec::new();
    let mut exit_code = -1;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
            _ => {}
        }
    }
    Ok(RemoteResult {
        exit_code,
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// Turn a non-zero remote `tar` exit into an error carrying its stderr.
fn check_remote(result: &RemoteResult) -> Result<()> {
    if result.exit_code == 0 {
        return Ok(());
    }
    let detail = result.stderr.trim();
    if detail.is_empty() {
        bail!(
            "the remote tar process exited with status {}",
            result.exit_code
        );
    }
    bail!(
        "the remote tar process failed (exit {}): {detail}",
        result.exit_code
    );
}

/// Compile exclude glob patterns into a set tested against each entry name.
fn compile_excludes(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern).with_context(|| format!("invalid exclude pattern {pattern:?}"))?,
        );
    }
    builder.build().context("building the exclude matcher")
}

/// Archive `source` (a file or directory) into the `archive` file, naming its
/// top-level entry `entry_name`. Synchronous; run on a blocking task.
fn pack(source: &Path, entry_name: &str, archive: &Path, excludes: &GlobSet) -> Result<()> {
    let file = std::fs::File::create(archive)
        .with_context(|| format!("creating {}", archive.display()))?;
    let mut builder = Builder::new(GzEncoder::new(file, Compression::default()));
    builder.follow_symlinks(false);

    let meta = std::fs::symlink_metadata(source)
        .with_context(|| format!("reading {}", source.display()))?;
    if meta.is_dir() {
        append_tree(&mut builder, source, Path::new(entry_name), excludes)?;
    } else {
        builder
            .append_path_with_name(source, entry_name)
            .with_context(|| format!("archiving the file {}", source.display()))?;
    }
    // `into_inner` finalises the tar; `finish` flushes the gzip trailer.
    builder
        .into_inner()
        .context("finalising the archive")?
        .finish()
        .context("finalising the gzip stream")?;
    Ok(())
}

/// Recursively archive `dir` under `archive_dir`, skipping any entry whose name
/// matches an exclude glob — and not descending into an excluded directory.
fn append_tree<W: Write>(
    builder: &mut Builder<W>,
    dir: &Path,
    archive_dir: &Path,
    excludes: &GlobSet,
) -> Result<()> {
    builder
        .append_dir(archive_dir, dir)
        .with_context(|| format!("archiving the directory {}", dir.display()))?;
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading an entry of {}", dir.display()))?;
        let name = entry.file_name();
        if excludes.is_match(Path::new(&name)) {
            continue;
        }
        let child = entry.path();
        let archive_child = archive_dir.join(&name);
        let meta = std::fs::symlink_metadata(&child)
            .with_context(|| format!("reading {}", child.display()))?;
        if meta.is_dir() {
            append_tree(builder, &child, &archive_child, excludes)?;
        } else {
            builder
                .append_path_with_name(&child, &archive_child)
                .with_context(|| format!("archiving {}", child.display()))?;
        }
    }
    Ok(())
}

/// Extract the `archive` file and move its `entry_name` entry to `dest`.
/// `dest` is the fully resolved final path: the caller has already applied
/// `cp` semantics (place-inside vs. replace), so this function is unaware of
/// the distinction. Synchronous; run on a blocking task.
fn unpack(archive: &Path, entry_name: &str, dest: &Path) -> Result<()> {
    // Extract into a staging directory beside `dest` — same filesystem, so the
    // final move is an atomic rename — then promote the one entry we asked for.
    let staging = tempfile::tempdir_in(local_parent(dest))
        .context("creating a staging directory for the download")?;
    let file = std::fs::File::open(archive).context("opening the downloaded archive")?;
    Archive::new(GzDecoder::new(file))
        .unpack(staging.path())
        .context("extracting the downloaded archive")?;

    let extracted = staging.path().join(entry_name);
    if !extracted.exists() {
        bail!("the archive did not contain the expected entry {entry_name:?}");
    }
    promote(&extracted, dest)
}

/// Replace `dest` with `produced`, removing whatever is at `dest` first.
/// Both paths must be on the same filesystem, so the move is a rename.
fn promote(produced: &Path, dest: &Path) -> Result<()> {
    if dest.symlink_metadata().is_ok() {
        remove_path(dest).with_context(|| format!("replacing the existing {}", dest.display()))?;
    }
    std::fs::rename(produced, dest)
        .with_context(|| format!("moving the result into place at {}", dest.display()))?;
    Ok(())
}

/// Remove a file, directory, or symlink, without following symlinks.
fn remove_path(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// The directory a local path sits in, treating a bare name as the current
/// directory.
fn local_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Split a remote path into the directory to `tar -C` into and the file name to
/// archive within it.
fn split_remote(path: &str) -> Result<(String, String)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("the remote path {path:?} is empty or the filesystem root");
    }
    let (dir, base) = match trimmed.rsplit_once('/') {
        Some(("", base)) => ("/".to_string(), base),
        Some((dir, base)) => (dir.to_string(), base),
        None => (".".to_string(), trimmed),
    };
    if base.is_empty() || base == "." || base == ".." {
        bail!("the remote path {path:?} has no usable file name");
    }
    Ok((dir, base.to_string()))
}

/// Quote a string as a single POSIX shell word.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_wraps_and_escapes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn split_remote_handles_each_shape() {
        assert_eq!(
            split_remote("/var/log/app").unwrap(),
            ("/var/log".to_string(), "app".to_string())
        );
        assert_eq!(
            split_remote("/app").unwrap(),
            ("/".to_string(), "app".to_string())
        );
        assert_eq!(
            split_remote("app").unwrap(),
            (".".to_string(), "app".to_string())
        );
        assert_eq!(
            split_remote("/var/log/app/").unwrap(),
            ("/var/log".to_string(), "app".to_string())
        );
        assert!(split_remote("/").is_err());
        assert!(split_remote("").is_err());
        assert!(split_remote("dir/..").is_err());
    }

    #[test]
    fn pack_then_unpack_round_trips_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("original.txt");
        std::fs::write(&source, b"hello transfer").unwrap();

        let archive = dir.path().join("bundle.tar");
        pack(&source, "renamed.txt", &archive, &GlobSet::empty()).unwrap();

        let dest = dir.path().join("result.txt");
        unpack(&archive, "renamed.txt", &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello transfer");
    }

    #[test]
    fn pack_then_unpack_round_trips_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("tree");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir(source.join("sub")).unwrap();
        std::fs::write(source.join("sub").join("b.txt"), b"bravo").unwrap();

        let archive = dir.path().join("bundle.tar");
        pack(&source, "copied", &archive, &GlobSet::empty()).unwrap();

        let dest = dir.path().join("result");
        unpack(&archive, "copied", &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            std::fs::read(dest.join("sub").join("b.txt")).unwrap(),
            b"bravo"
        );
    }

    #[test]
    fn unpack_rejects_a_missing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("original.txt");
        std::fs::write(&source, b"data").unwrap();
        let archive = dir.path().join("bundle.tar");
        pack(&source, "present.txt", &archive, &GlobSet::empty()).unwrap();

        let dest = dir.path().join("result.txt");
        assert!(unpack(&archive, "absent.txt", &dest).is_err());
    }

    #[test]
    fn unpack_replaces_an_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("original.txt");
        std::fs::write(&source, b"fresh content").unwrap();
        let archive = dir.path().join("bundle.tar");
        pack(&source, "entry.txt", &archive, &GlobSet::empty()).unwrap();

        let dest = dir.path().join("result.txt");
        std::fs::write(&dest, b"stale content").unwrap();
        unpack(&archive, "entry.txt", &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"fresh content");
    }

    #[test]
    fn unpack_into_existing_directory_places_entry_inside() {
        // `cp` semantics: when `dest` is an existing directory, the downloaded
        // entry lands inside it under its archive name, rather than replacing
        // the whole directory.
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("payload.txt");
        std::fs::write(&source, b"payload").unwrap();
        let archive = dir.path().join("bundle.tar");
        pack(&source, "payload.txt", &archive, &GlobSet::empty()).unwrap();

        let dest = dir.path().join("inbox");
        std::fs::create_dir(&dest).unwrap();
        // A pre-existing sibling must survive — the directory is merged, not
        // replaced.
        std::fs::write(dest.join("sibling.txt"), b"keep me").unwrap();

        let target = resolve_download_target(&dest, "payload.txt");
        unpack(&archive, "payload.txt", &target).unwrap();

        assert_eq!(std::fs::read(dest.join("payload.txt")).unwrap(), b"payload");
        assert_eq!(std::fs::read(dest.join("sibling.txt")).unwrap(), b"keep me");
    }

    #[test]
    fn resolve_upload_target_places_inside_existing_remote_directory() {
        // `cp` semantics again, mirrored on the upload side: an existing
        // remote directory becomes the parent and the entry takes the local
        // file's name.
        let local = Path::new("/home/user/payload.txt");
        let (dir, base) = resolve_upload_target(local, "/srv/inbox", true).unwrap();
        assert_eq!(dir, "/srv/inbox");
        assert_eq!(base, "payload.txt");

        // A trailing slash on a directory must not produce an empty target.
        let (dir, base) = resolve_upload_target(local, "/srv/inbox/", true).unwrap();
        assert_eq!(dir, "/srv/inbox");
        assert_eq!(base, "payload.txt");

        // The root, were it the target directory, must stay `/` after trim.
        let (dir, base) = resolve_upload_target(local, "/", true).unwrap();
        assert_eq!(dir, "/");
        assert_eq!(base, "payload.txt");
    }

    #[test]
    fn resolve_upload_target_replaces_a_non_directory_remote() {
        // Replace semantics for the non-directory case: the remote path is
        // split into (parent, name) and the local entry takes the remote name
        // — this is how a rename like `cp a.txt /srv/b.txt` is expressed.
        let local = Path::new("/home/user/a.txt");
        let (dir, base) = resolve_upload_target(local, "/srv/b.txt", false).unwrap();
        assert_eq!(dir, "/srv");
        assert_eq!(base, "b.txt");
    }

    #[test]
    fn pack_excludes_matching_names() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("project");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("keep.rs"), b"src").unwrap();
        std::fs::write(source.join("debug.log"), b"log").unwrap();
        std::fs::create_dir(source.join("target")).unwrap();
        std::fs::write(source.join("target").join("big"), b"artifact").unwrap();

        let excludes = compile_excludes(&["target".to_string(), "*.log".to_string()]).unwrap();
        let archive = dir.path().join("bundle.tar");
        pack(&source, "project", &archive, &excludes).unwrap();

        let dest = dir.path().join("result");
        unpack(&archive, "project", &dest).unwrap();
        assert!(dest.join("keep.rs").exists());
        assert!(!dest.join("debug.log").exists());
        assert!(!dest.join("target").exists());
    }
}
