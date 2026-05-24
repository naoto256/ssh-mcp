//! Transfer implementations for POSIX remotes (Linux / macOS / *BSD —
//! anything that uses a Bourne-family shell and ships `tar` / `find` /
//! `rm` / `mkdir` / `test -d`). Each `pub(super)` function here is the
//! body of the corresponding arm in `impl RemoteOs` over in `mod.rs`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use russh::{Channel, ChannelMsg, client};
use tempfile::NamedTempFile;

use super::common::{
    TransferStats, check_remote, compile_excludes, local_parent, pack, pack_entries,
    resolve_download_target, run_download, run_simple, run_upload, unpack, unpack_into,
};

/// Download a remote file or directory to `local_path`.
///
/// The destination follows `cp` semantics: if `local_path` is an existing
/// directory the downloaded entry is placed inside it under its remote base
/// name; otherwise the downloaded entry replaces `local_path`. An entry whose
/// name matches an `exclude` glob is left out of the archive.
pub(super) async fn download(
    mut channel: Channel<client::Msg>,
    remote_path: &str,
    local_path: &Path,
    exclude: &[String],
    timeout: Duration,
    encoding: &'static encoding_rs::Encoding,
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
    check_remote(&result, encoding)?;

    let archive = tar_file.path().to_path_buf();
    let dest = target;
    let entry = base.clone();
    tokio::task::spawn_blocking(move || unpack(&archive, &entry, &dest))
        .await
        .context("the archive extraction task failed")??;
    Ok(TransferStats { bytes })
}

/// Upload a local file or directory to `remote_path` by streaming a tar archive
/// over `channel`. The caller must report whether `remote_path` already exists
/// as a directory: when it does, `cp` semantics place the local entry inside
/// it under its local base name; otherwise the local entry replaces whatever
/// is at `remote_path`. The remote parent directory is created if it is
/// missing. An entry whose name matches an `exclude` glob is left out.
pub(super) async fn upload(
    mut channel: Channel<client::Msg>,
    local_path: &Path,
    remote_path: &str,
    remote_is_existing_dir: bool,
    exclude: &[String],
    timeout: Duration,
    encoding: &'static encoding_rs::Encoding,
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
    check_remote(&result, encoding)?;
    Ok(TransferStats { bytes })
}

/// Pack a chosen subset of files under `source_root` into a tar archive and
/// stream it into `target_dir` on the remote. The archive entry names equal
/// the supplied relative paths (e.g. `proj/src/foo.rs`), so on extraction
/// they land at `<target_dir>/<rel>`. Returns the archive byte count.
pub(super) async fn upload_entries(
    mut channel: Channel<client::Msg>,
    source_root: &Path,
    source_root_name: &Path,
    rel_paths: &[PathBuf],
    target_dir: &str,
    timeout: Duration,
    encoding: &'static encoding_rs::Encoding,
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
    check_remote(&result, encoding)?;
    Ok(bytes)
}

/// Ask the remote to tar a chosen subset of files under `source_root`,
/// stream it back, and extract the archive into `dest_root` locally
/// (creating `dest_root` if it does not yet exist). Returns the compressed
/// archive byte count.
pub(super) async fn download_entries(
    mut channel: Channel<client::Msg>,
    source_root: &str,
    rel_paths_inside_source: &[PathBuf],
    dest_root: &Path,
    timeout: Duration,
    encoding: &'static encoding_rs::Encoding,
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
    check_remote(&result, encoding)?;

    let archive = tar_file.path().to_path_buf();
    let dest = dest_root.to_path_buf();
    tokio::task::spawn_blocking(move || unpack_into(&archive, &dest))
        .await
        .context("the archive extraction task failed")??;
    Ok(bytes)
}

/// Remove a list of relative paths under `root` on the remote with
/// `rm -rf`. Used by `sync_*` to apply the change set's `Delete` entries.
pub(super) async fn delete_remote(
    mut channel: Channel<client::Msg>,
    root: &str,
    rel_paths: &[PathBuf],
    timeout: Duration,
    encoding: &'static encoding_rs::Encoding,
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
    check_remote(&result, encoding)?;
    Ok(())
}

/// Detect whether a remote path is an existing directory by running a short
/// `test -d` over `channel`. A non-zero exit is taken to mean "not a directory"
/// — this covers both "does not exist" and "exists but is a file or symlink",
/// which take the same `cp` branch (the local entry replaces the path).
pub(super) async fn remote_is_dir(mut channel: Channel<client::Msg>, path: &str) -> Result<bool> {
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
}
