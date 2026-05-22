//! File and directory transfer over an SSH channel, via `tar`.
//!
//! A transfer streams a gzip-compressed tar archive across one channel: a
//! download runs `tar` on the remote and extracts the stream locally; an
//! upload builds the archive locally and feeds it to a remote `tar`. `tar`
//! carries files and directories alike, and the stream is handled as raw
//! bytes throughout — never decoded as text — so binary content survives
//! intact.

use std::io::Write;
use std::path::Path;
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

/// Download a remote file or directory into `local_path` by streaming a tar
/// archive over `channel`, replacing `local_path` if it already exists. An
/// entry whose name matches an `exclude` glob is left out.
pub async fn download(
    mut channel: Channel<client::Msg>,
    remote_path: &str,
    local_path: &Path,
    exclude: &[String],
    timeout: Duration,
) -> Result<TransferStats> {
    let parent = local_parent(local_path);
    if !parent.is_dir() {
        bail!("the local directory {} does not exist", parent.display());
    }

    let (dir, base) = split_remote(remote_path)?;
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
    let dest = local_path.to_path_buf();
    let entry = base.clone();
    tokio::task::spawn_blocking(move || unpack(&archive, &entry, &dest))
        .await
        .context("the archive extraction task failed")??;
    Ok(TransferStats { bytes })
}

/// Upload a local file or directory to `remote_path` by streaming a tar archive
/// over `channel`. The remote parent directory is created if it is missing. An
/// entry whose name matches an `exclude` glob is left out.
pub async fn upload(
    mut channel: Channel<client::Msg>,
    local_path: &Path,
    remote_path: &str,
    exclude: &[String],
    timeout: Duration,
) -> Result<TransferStats> {
    if !local_path.exists() {
        bail!("the local path {} does not exist", local_path.display());
    }
    let excludes = compile_excludes(exclude)?;

    let (dir, base) = split_remote(remote_path)?;
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
/// Synchronous; run on a blocking task.
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
