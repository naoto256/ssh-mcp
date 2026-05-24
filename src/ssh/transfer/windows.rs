//! Transfer implementations for Windows remotes (OpenSSH server on
//! Windows 10/11; default shell is typically PowerShell or cmd.exe).
//! Each `pub(super)` function here is the body of the corresponding arm
//! in `impl RemoteOs` over in `mod.rs`. The shape mirrors `posix.rs`
//! but the helper substrate is `powershell.exe -EncodedCommand …`
//! driving `tar.exe` (libarchive, shipped with Windows 10 1803+) and
//! `Test-Path` / `Remove-Item`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use russh::{Channel, ChannelMsg, client};
use tempfile::NamedTempFile;

use super::common::{
    TransferStats, check_remote, compile_excludes, local_parent, pack, pack_entries,
    resolve_download_target, run_download, run_simple, run_upload, unpack, unpack_into,
};

/// Download from a Windows remote. The remote runs `tar.exe -czf -` to
/// produce a gzip-tar archive on stdout; the local side extracts it the
/// same way as for POSIX, so the cp-merge resolution and the staging-then-
/// rename promote logic carry over without change.
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

    // tar.exe's `--exclude` accepts the same name-pattern shape as GNU tar
    // (libarchive parity), so the existing exclude list flows through.
    // Symmetric to upload: PowerShell runs tar.exe and pipes its
    // stdout (binary tar.gz bytes) back to us. Arguments are built as a
    // PowerShell array literal so each item is quoted independently —
    // safer than building a flat string when paths contain spaces or
    // backslashes.
    let mut ps_args = vec![
        "'-C'".to_string(),
        format!("'{}'", ps_single_quote(&dir)),
        "'-czf'".to_string(),
        "'-'".to_string(),
    ];
    for pattern in exclude {
        ps_args.push(format!("'--exclude={}'", ps_single_quote(pattern)));
    }
    ps_args.push("'--'".to_string());
    ps_args.push(format!("'{}'", ps_single_quote(&base)));
    let command = ps_tar_create_to_stdout_command(&ps_args);

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

/// Upload to a Windows remote. The local side builds the gzip-tar archive
/// the same way as for POSIX. The remote side runs entirely inside one
/// PowerShell script: it ensures the destination directory exists, then
/// spawns `tar.exe` with its stdin connected to the SSH channel input
/// stream — `System.Diagnostics.Process` plus `[Console]::OpenStandardInput`
/// gives a raw binary pipe, with `[Console]::OutputEncoding = UTF-8` so
/// any path or progress messages come back cleanly. The cmd.exe shell
/// is not involved.
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

    let command = ps_tar_extract_stdin_command(&dir);
    let input =
        tokio::fs::File::from_std(tar_file.reopen().context("opening the temporary archive")?);

    let result = tokio::time::timeout(timeout, run_upload(&mut channel, &command, input))
        .await
        .map_err(|_| anyhow!("the transfer timed out after {} seconds", timeout.as_secs()))??;
    check_remote(&result, encoding)?;
    Ok(TransferStats { bytes })
}

/// Pack chosen files into a tar archive, then untar through PowerShell /
/// `tar.exe` with `-C` for the destination directory.
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

    let command = ps_tar_extract_stdin_command(target_dir);
    let input =
        tokio::fs::File::from_std(tar_file.reopen().context("opening the temporary archive")?);
    let result = tokio::time::timeout(timeout, run_upload(&mut channel, &command, input))
        .await
        .map_err(|_| anyhow!("the transfer timed out after {} seconds", timeout.as_secs()))??;
    check_remote(&result, encoding)?;
    Ok(bytes)
}

/// PowerShell runs `tar.exe -C SOURCE_ROOT -czf - -- rel1 rel2 ...` and
/// forwards `tar.exe`'s binary stdout back over the SSH channel.
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
    let mut ps_args = vec![
        "'-C'".to_string(),
        format!("'{}'", ps_single_quote(source_root)),
        "'-czf'".to_string(),
        "'-'".to_string(),
        "'--'".to_string(),
    ];
    for rel in rel_paths_inside_source {
        ps_args.push(format!("'{}'", ps_single_quote(&rel.to_string_lossy())));
    }
    let command = ps_tar_create_to_stdout_command(&ps_args);

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

/// PowerShell `Remove-Item` per relative path, rooted at `root`. Quoting
/// is single-quote PS so backslashes pass through untouched.
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
    // Build a PowerShell script that joins each rel path to root and
    // removes it. Use Remove-Item with -Recurse -Force so directories
    // and read-only files alike are dispatched.
    let mut paths_literal = String::new();
    for (i, rel) in rel_paths.iter().enumerate() {
        if i > 0 {
            paths_literal.push(',');
        }
        paths_literal.push('\'');
        paths_literal.push_str(&ps_single_quote(&rel.to_string_lossy()));
        paths_literal.push('\'');
    }
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $root = '{root}'\n\
         foreach ($rel in @({paths})) {{\n\
           $p = Join-Path $root $rel\n\
           if (Test-Path -LiteralPath $p) {{ Remove-Item -LiteralPath $p -Recurse -Force }}\n\
         }}",
        root = ps_single_quote(root),
        paths = paths_literal
    );
    let command = format!(
        "powershell -NoProfile -EncodedCommand {}",
        powershell_encoded_command(&script)
    );
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

/// `Test-Path -PathType Container` is the canonical "is this a directory?"
/// test on Windows — robust across modern Windows builds (including the
/// ARM64 one that broke the older `if exist DIR\*` cmd.exe idiom). Exit
/// code conveys the answer with no parse.
pub(super) async fn remote_is_dir(mut channel: Channel<client::Msg>, path: &str) -> Result<bool> {
    let script = format!(
        "if (Test-Path -LiteralPath '{p}' -PathType Container) {{ exit 0 }} else {{ exit 1 }}",
        p = ps_single_quote(path)
    );
    let command = format!(
        "powershell -NoProfile -EncodedCommand {}",
        powershell_encoded_command(&script)
    );
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

/// Resolve where an uploaded archive should land on a Windows remote. Same
/// cp-merge semantics as the POSIX side, just with Windows path splitting.
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
        let dir = remote_path.trim_end_matches(['/', '\\']);
        let dir = if dir.is_empty() {
            "\\".to_string()
        } else {
            dir.to_string()
        };
        Ok((dir, local_base))
    } else {
        split_remote(remote_path)
    }
}

/// Split a Windows-style remote path into the directory it sits under and
/// its base name. Both `/` and `\` are accepted as separators — the user
/// or the remote can use either. The output keeps whichever slash was in
/// the input, so the path reads naturally back to the caller.
fn split_remote(path: &str) -> Result<(String, String)> {
    let trimmed = path.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        bail!("the remote path {path:?} is empty or the filesystem root");
    }
    let (dir, base) = match trimmed.rfind(['/', '\\']) {
        Some(i) => {
            let raw_dir = &trimmed[..i];
            let dir = if raw_dir.is_empty() {
                // Path was something like `\foo` — root of the current drive.
                "\\".to_string()
            } else if raw_dir.len() == 2 && raw_dir.as_bytes()[1] == b':' {
                // Drive-rooted path like `C:\foo` — keep the trailing slash
                // so `cd /d C:\` works.
                format!("{raw_dir}\\")
            } else {
                raw_dir.to_string()
            };
            (dir, trimmed[i + 1..].to_string())
        }
        None => (".".to_string(), trimmed.to_string()),
    };
    if base.is_empty() || base == "." || base == ".." {
        bail!("the remote path {path:?} has no usable file name");
    }
    Ok((dir, base))
}

/// PowerShell single-quote escape — double the embedded single quotes.
/// A sibling copy lives in `changeset::` for the walk-command builders;
/// both share the same trivial rule so the two copies will not drift.
fn ps_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

/// Encode a PowerShell script for `powershell -EncodedCommand`: UTF-16 LE
/// then base64. Sibling of the one in `changeset::`.
fn powershell_encoded_command(script: &str) -> String {
    use base64::engine::Engine;
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for u in utf16 {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Build the PowerShell `powershell -NoProfile -EncodedCommand` invocation
/// that runs `tar.exe` with the provided argument list and forwards its
/// stdout (binary) to the SSH channel. Used by the download path. Each
/// element of `ps_args` is already a PowerShell-literal expression
/// (typically a single-quoted string), and they are joined with `,` into
/// an `ArgumentList`-style invocation.
fn ps_tar_create_to_stdout_command(ps_args: &[String]) -> String {
    let args_literal = ps_args.join(",");
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $args = @({args})\n\
         # CreateProcess takes an Arguments *string*; build one whose tokens\n\
         # are quoted so paths with spaces/backslashes round-trip cleanly.\n\
         $argString = ($args | ForEach-Object {{ '\"' + ($_ -replace '\"', '\\\"') + '\"' }}) -join ' '\n\
         $psi = New-Object System.Diagnostics.ProcessStartInfo\n\
         $psi.FileName = 'tar.exe'\n\
         $psi.Arguments = $argString\n\
         $psi.UseShellExecute = $false\n\
         $psi.RedirectStandardOutput = $true\n\
         $p = [System.Diagnostics.Process]::Start($psi)\n\
         $p.StandardOutput.BaseStream.CopyTo([Console]::OpenStandardOutput())\n\
         $p.WaitForExit()\n\
         exit $p.ExitCode",
        args = args_literal
    );
    format!(
        "powershell -NoProfile -EncodedCommand {}",
        powershell_encoded_command(&script)
    )
}

/// Build the PowerShell `powershell -NoProfile -EncodedCommand` invocation
/// that creates `dir` if missing and runs `tar.exe -C <dir> -xzf -`
/// against raw stdin. Used by both the single-entry `upload` and the
/// partial-tree `upload_entries`.
fn ps_tar_extract_stdin_command(dir: &str) -> String {
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()\n\
         $dir = '{dir}'\n\
         if (-not (Test-Path -LiteralPath $dir -PathType Container)) {{\n\
           New-Item -ItemType Directory -Force -Path $dir | Out-Null\n\
         }}\n\
         $psi = New-Object System.Diagnostics.ProcessStartInfo\n\
         $psi.FileName = 'tar.exe'\n\
         $psi.Arguments = \"-C `\"$dir`\" -xzf -\"\n\
         $psi.UseShellExecute = $false\n\
         $psi.RedirectStandardInput = $true\n\
         $p = [System.Diagnostics.Process]::Start($psi)\n\
         [Console]::OpenStandardInput().CopyTo($p.StandardInput.BaseStream)\n\
         $p.StandardInput.Close()\n\
         $p.WaitForExit()\n\
         exit $p.ExitCode",
        dir = ps_single_quote(dir)
    );
    format!(
        "powershell -NoProfile -EncodedCommand {}",
        powershell_encoded_command(&script)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_remote_handles_each_shape() {
        // Drive-rooted paths keep their drive in the dir half so `cd /d`
        // works on either slash style.
        assert_eq!(
            split_remote("C:\\Users\\naoto\\proj").unwrap(),
            ("C:\\Users\\naoto".to_string(), "proj".to_string())
        );
        assert_eq!(
            split_remote("C:/Users/naoto/proj").unwrap(),
            ("C:/Users/naoto".to_string(), "proj".to_string())
        );
        // Drive root: dir is `C:\` so `cd /d C:\` lands at the drive root.
        assert_eq!(
            split_remote("C:\\app").unwrap(),
            ("C:\\".to_string(), "app".to_string())
        );
        // Bare drive-letterless root.
        assert_eq!(
            split_remote("\\app").unwrap(),
            ("\\".to_string(), "app".to_string())
        );
        // Bare name relative to the SSH login directory.
        assert_eq!(
            split_remote("app").unwrap(),
            (".".to_string(), "app".to_string())
        );
        // A trailing slash is stripped; the rest of the split is unchanged.
        assert_eq!(
            split_remote("C:\\app\\").unwrap(),
            ("C:\\".to_string(), "app".to_string())
        );
        // Mixed separators are normalised by taking whichever the last one
        // is — both work for tar and cd.
        assert_eq!(
            split_remote("C:\\Users/naoto\\proj").unwrap(),
            ("C:\\Users/naoto".to_string(), "proj".to_string())
        );
        assert!(split_remote("").is_err());
        assert!(split_remote("\\").is_err());
    }

    #[test]
    fn resolve_upload_target_handles_dir_and_replace() {
        let local = Path::new("/Users/naoto/code/proj");
        // Existing remote directory: the local entry lands inside under
        // its own basename.
        let (dir, base) =
            resolve_upload_target(local, "C:\\Users\\naoto\\workspaces", true).unwrap();
        assert_eq!(dir, "C:\\Users\\naoto\\workspaces");
        assert_eq!(base, "proj");
        // Non-existing target: replace semantics. The local entry takes
        // the remote name.
        let (dir, base) = resolve_upload_target(local, "C:\\Users\\naoto\\dist", false).unwrap();
        assert_eq!(dir, "C:\\Users\\naoto");
        assert_eq!(base, "dist");
    }
}
