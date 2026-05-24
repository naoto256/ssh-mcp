//! Shared helpers used by both the POSIX and Windows transfer paths:
//! channel I/O loops (`run_download` / `run_upload` / `run_capture` /
//! `run_simple`), tar pack / unpack, exclude compilation, and the
//! single-encoding-aware error decoder. None of these touch shell or
//! PowerShell syntax — they are the OS-neutral plumbing each side
//! composes on top of.

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
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Statistics from one completed transfer.
#[derive(Debug, Clone)]
pub struct TransferStats {
    /// The size of the compressed archive that crossed the connection, in bytes.
    pub bytes: u64,
}

/// The outcome of a remote helper process (`tar`, PowerShell walk,
/// `rm` / `Remove-Item`, ...). `stderr` is kept as raw bytes so that
/// the appropriate decoder (UTF-8 for POSIX, whatever code page the
/// connection cached for Windows) can be applied at the point of
/// display, rather than lossily decoded at capture and then re-mojibaked
/// when shown to the user.
pub(super) struct RemoteResult {
    pub exit_code: i32,
    pub stderr: Vec<u8>,
}

/// Run the remote archive command and stream its stdout to `sink`, returning
/// the remote result and the number of bytes written.
pub(super) async fn run_download<W: AsyncWrite + Unpin>(
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
    Ok((RemoteResult { exit_code, stderr }, bytes))
}

/// Run the remote extract command and stream `input` into its stdin.
pub(super) async fn run_upload<R: AsyncRead + Unpin>(
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
    Ok(RemoteResult { exit_code, stderr })
}

/// Synchronous-sink variant of `run_download` for in-memory capture.
pub(super) async fn run_capture(
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
    Ok((RemoteResult { exit_code, stderr }, bytes))
}

/// Run a command that produces no output we care about, returning its exit
/// status and stderr.
pub(super) async fn run_simple(
    channel: &mut Channel<client::Msg>,
    command: &str,
) -> Result<RemoteResult> {
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
    Ok(RemoteResult { exit_code, stderr })
}

/// Turn a non-zero remote `tar` exit into an error carrying its stderr.
/// Decoding happens here, not at capture: the raw bytes from the remote
/// could be in any console code page (CP932 on Japanese Windows, UTF-8
/// on POSIX, ...), and we want the eventual error string to be
/// well-formed UTF-8 for the daemon's callers.
pub(super) fn check_remote(
    result: &RemoteResult,
    encoding: &'static encoding_rs::Encoding,
) -> Result<()> {
    if result.exit_code == 0 {
        return Ok(());
    }
    let (stderr_text, _, _) = encoding.decode(&result.stderr);
    let detail = stderr_text.trim();
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

/// Capture stdout from a one-shot remote command, returning it as a single
/// string. Errors carry the remote stderr.
///
/// `encoding` is used only for *stderr* (when surfacing the failure via
/// `check_remote`). Stdout is decoded as UTF-8 because the only caller
/// is the sync gate's walk command, whose PowerShell / `find` script
/// explicitly forces UTF-8 output regardless of the remote console code
/// page — decoding those UTF-8 bytes with the connection's encoding
/// (CP932 etc.) would re-mojibake them. This function is OS-neutral:
/// both POSIX and Windows walks run through the same code path.
pub async fn exec_capture(
    mut channel: Channel<client::Msg>,
    command: &str,
    timeout: Duration,
    encoding: &'static encoding_rs::Encoding,
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
    check_remote(&result, encoding)?;
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Compile exclude glob patterns into a set tested against each entry name.
pub(super) fn compile_excludes(patterns: &[String]) -> Result<GlobSet> {
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
pub(super) fn pack(
    source: &Path,
    entry_name: &str,
    archive: &Path,
    excludes: &GlobSet,
) -> Result<()> {
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

/// Synchronous counterpart of `upload_entries`'s pack step.
pub(super) fn pack_entries(
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

/// Extract the `archive` file and move its `entry_name` entry to `dest`.
/// `dest` is the fully resolved final path: the caller has already applied
/// `cp` semantics (place-inside vs. replace), so this function is unaware of
/// the distinction. Synchronous; run on a blocking task.
pub(super) fn unpack(archive: &Path, entry_name: &str, dest: &Path) -> Result<()> {
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

/// Extract an archive's contents straight into `dest_dir`, merging into
/// whatever already lives there. Files inside the archive are overwritten if
/// they collide with existing ones; files outside the archive are left
/// alone.
pub(super) fn unpack_into(archive: &Path, dest_dir: &Path) -> Result<()> {
    let file = std::fs::File::open(archive).context("opening the downloaded archive")?;
    let mut archive = Archive::new(GzDecoder::new(file));
    // The default behaviour overwrites existing files; we want that.
    archive
        .unpack(dest_dir)
        .context("extracting the downloaded archive")?;
    Ok(())
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
pub(super) fn local_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Resolve where a downloaded entry should land. `cp` semantics: if the
/// caller-supplied destination is already a directory, the entry is placed
/// inside it under its remote base name; otherwise the destination is taken
/// as-is and replaces whatever was there.
pub(super) fn resolve_download_target(dest: &Path, entry_name: &str) -> PathBuf {
    if dest.is_dir() {
        dest.join(entry_name)
    } else {
        dest.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn diagnostic_pack_entry_names() {
        // Dump the entry names a `pack()` produces so we can confirm
        // whether the archive really carries the requested top-level
        // directory prefix.
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("proj");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("Cargo.toml"), b"config").unwrap();
        std::fs::create_dir(source.join("src")).unwrap();
        std::fs::write(source.join("src").join("main.rs"), b"code").unwrap();

        let archive = dir.path().join("bundle.tar");
        pack(&source, "proj", &archive, &GlobSet::empty()).unwrap();

        let file = std::fs::File::open(&archive).unwrap();
        let mut ar = Archive::new(GzDecoder::new(file));
        let mut names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                e.path().unwrap().to_string_lossy().into_owned()
            })
            .collect();
        names.sort();
        println!("ARCHIVE_ENTRIES: {names:?}");
        // The assertion: every entry must be under `proj/`.
        for name in &names {
            assert!(
                name.starts_with("proj"),
                "entry {name:?} is missing the proj/ prefix"
            );
        }
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
