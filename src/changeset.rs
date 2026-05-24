//! The per-file change-set engine.
//!
//! A transfer is reduced to a list of per-file operations — `Create`,
//! `Update`, `Delete`, `Skip` — by walking both sides, hashing each file,
//! and pairing the two listings. The transfer then moves only the entries
//! that need moving, and the policy gate evaluates entries one by one.
//!
//! The engine knows about two sides of a transfer (a local tree, a remote
//! tree) but is otherwise direction-agnostic: callers tell it which side is
//! "source" and which is "dest".

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// A sha-256 digest, the unit of file identity used by the engine.
pub type Hash = [u8; 32];

/// What needs to happen to a single file to bring the destination into line
/// with the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeOp {
    /// The file is on the source side but not the destination side.
    Create,
    /// Both sides have the file but the source's content differs.
    Update,
    /// Both sides have the file and the content matches.
    Skip,
    /// The destination has the file and the source does not (mirror only).
    Delete,
}

impl ChangeOp {
    /// A short verb suitable for the trace body line (`"create foo.txt"`).
    pub fn verb(self) -> &'static str {
        match self {
            ChangeOp::Create => "create",
            ChangeOp::Update => "update",
            ChangeOp::Skip => "skip",
            ChangeOp::Delete => "delete",
        }
    }
}

/// One file's place in the change set.
#[derive(Debug, Clone)]
pub struct Entry {
    pub op: ChangeOp,
    /// Path relative to the transfer's root, e.g. `src/foo.rs`.
    pub rel_path: PathBuf,
}

/// A computed change set: every file the engine considered, classified.
#[derive(Debug, Clone, Default)]
pub struct ChangeSet {
    pub entries: Vec<Entry>,
}

impl ChangeSet {
    pub fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for entry in &self.entries {
            match entry.op {
                ChangeOp::Create => counts.created += 1,
                ChangeOp::Update => counts.updated += 1,
                ChangeOp::Skip => counts.skipped += 1,
                ChangeOp::Delete => counts.deleted += 1,
            }
        }
        counts
    }

    /// Every entry that actually moves bytes — the ones the transfer must
    /// pack into the tar archive on the source side.
    pub fn outgoing(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.op, ChangeOp::Create | ChangeOp::Update))
    }

    /// Every entry that requires policy evaluation: anything except `Skip`,
    /// since a hash-matched file is a no-op the model never had to ask for.
    pub fn evaluable(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| e.op != ChangeOp::Skip)
    }
}

/// File-count summary for the tool's return value.
#[derive(
    Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct Counts {
    pub created: u32,
    pub updated: u32,
    pub skipped: u32,
    pub deleted: u32,
}

/// Compare a source listing to a destination listing and produce the change
/// set. `mirror` controls whether files present only on the destination are
/// `Delete` entries (mirror semantics) or omitted altogether (additive).
pub fn compute(
    source: HashMap<PathBuf, Hash>,
    dest: HashMap<PathBuf, Hash>,
    mirror: bool,
) -> ChangeSet {
    let mut entries = Vec::with_capacity(source.len());
    for (rel, src_hash) in &source {
        let op = match dest.get(rel) {
            Some(dest_hash) if dest_hash == src_hash => ChangeOp::Skip,
            Some(_) => ChangeOp::Update,
            None => ChangeOp::Create,
        };
        entries.push(Entry {
            op,
            rel_path: rel.clone(),
        });
    }
    if mirror {
        for rel in dest.keys() {
            if !source.contains_key(rel) {
                entries.push(Entry {
                    op: ChangeOp::Delete,
                    rel_path: rel.clone(),
                });
            }
        }
    }
    // Stable, alphabetical order so two runs against the same trees produce
    // the same trace and the same policy prompt.
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    ChangeSet { entries }
}

/// Compile exclude glob patterns once. Each pattern is matched against an
/// individual path component name (e.g. `target`, `*.log`), matching the
/// `put_file` exclude shape the user already configured.
pub fn compile_excludes(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern).with_context(|| format!("invalid exclude pattern {pattern:?}"))?,
        );
    }
    builder.build().context("building the exclude matcher")
}

/// Does this path have any component that matches an exclude glob?
fn is_excluded(rel: &Path, excludes: &GlobSet) -> bool {
    rel.components()
        .any(|c| excludes.is_match(Path::new(c.as_os_str())))
}

/// Walk a local tree, hashing every file. `root` may be a single file or a
/// directory — both are handled, mirroring the transfer surface. The
/// returned map keys are paths relative to `root`'s parent (for a file root
/// the single key is the file's name; for a directory root, keys are
/// `dir_name/...`).
pub fn walk_local(
    root: &Path,
    base_name: &Path,
    excludes: &GlobSet,
) -> Result<HashMap<PathBuf, Hash>> {
    let meta = match std::fs::symlink_metadata(root) {
        Ok(meta) => meta,
        // A destination that does not exist yet is a perfectly normal state
        // for a transfer's first run — every file becomes `Create`.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", root.display())),
    };
    let mut out = HashMap::new();
    if meta.is_file() {
        let hash = hash_file(root)?;
        out.insert(base_name.to_path_buf(), hash);
        return Ok(out);
    }
    if !meta.is_dir() {
        // A symlink or special file: not supported, skip silently rather
        // than fail the whole transfer.
        return Ok(out);
    }
    for entry in WalkDir::new(root) {
        let entry = entry.with_context(|| format!("walking {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel_inside = path
            .strip_prefix(root)
            .with_context(|| format!("relativising {}", path.display()))?;
        if is_excluded(rel_inside, excludes) {
            continue;
        }
        let rel = base_name.join(rel_inside);
        let hash = hash_file(path)?;
        out.insert(rel, hash);
    }
    Ok(out)
}

/// Build the remote shell command that gracefully no-ops when the walk root
/// does not exist on the host — a perfectly normal state for the first run
/// of a transfer. Returns empty stdout in that case.
pub fn remote_walk_command_safe(root: &str, name_only_excludes: &[String]) -> String {
    let inner = remote_walk_command(root, name_only_excludes);
    format!("if [ -d {} ]; then {inner}; fi", shell_quote(root))
}

/// Paths-only walk: the hook gate only needs the *set of paths* that would
/// be touched, never the hashes. Building the change set from path
/// existence alone (source-only → Create, both → Update, dest-only →
/// Delete) is enough to evaluate `Edit(path)` per entry.
///
/// Walking by paths instead of hashes is what makes the hook gate cheap —
/// for a 10 k file tree the local cost is a single `WalkDir`, and the
/// remote cost is a single `find -print0` with no `sha256sum` fan-out.
pub fn walk_local_paths(
    root: &Path,
    base_name: &Path,
    excludes: &GlobSet,
) -> Result<HashSet<PathBuf>> {
    let meta = match std::fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", root.display())),
    };
    let mut out = HashSet::new();
    if meta.is_file() {
        out.insert(base_name.to_path_buf());
        return Ok(out);
    }
    if !meta.is_dir() {
        return Ok(out);
    }
    for entry in WalkDir::new(root) {
        let entry = entry.with_context(|| format!("walking {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel_inside = path
            .strip_prefix(root)
            .with_context(|| format!("relativising {}", path.display()))?;
        if is_excluded(rel_inside, excludes) {
            continue;
        }
        out.insert(base_name.join(rel_inside));
    }
    Ok(out)
}

/// Build the paths-only counterpart of [`remote_walk_command_safe`]: same
/// directory check and prune logic but stopping at `-print0`, since the
/// hook never needs the hashes.
pub fn remote_paths_walk_command_safe(root: &str, name_only_excludes: &[String]) -> String {
    let mut cmd = format!("cd {} && find . ", shell_quote(root));
    if !name_only_excludes.is_empty() {
        cmd.push_str("\\( ");
        for (i, pat) in name_only_excludes.iter().enumerate() {
            if i > 0 {
                cmd.push_str(" -o ");
            }
            cmd.push_str(&format!("-name {}", shell_quote(pat)));
        }
        cmd.push_str(" \\) -prune -o ");
    }
    cmd.push_str("-type f -print0");
    format!("if [ -d {} ]; then {cmd}; fi", shell_quote(root))
}

/// Windows counterpart of [`remote_walk_command_safe`]: PowerShell
/// recursive enumeration that emits `<sha256 hex>  <relpath>` per line,
/// the same shape the POSIX `sha256sum` output uses. Empty stdout when
/// the root does not exist, so the diff just sees no entries on that
/// side. Excludes are matched per-segment with `-like` wildcards so the
/// same `target` / `*.log` / `.git` patterns the inventory already uses
/// work without translation.
pub fn remote_walk_command_safe_windows(root: &str, name_only_excludes: &[String]) -> String {
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()\n\
         $root = '{root}'\n\
         if (-not (Test-Path -LiteralPath $root -PathType Container)) {{ return }}\n\
         $rootAbs = (Resolve-Path -LiteralPath $root).Path\n\
         $excludes = @({excludes})\n\
         $prefix = $rootAbs.TrimEnd('\\').Length + 1\n\
         Get-ChildItem -LiteralPath $rootAbs -File -Recurse -Force | Where-Object {{\n\
           $segments = $_.FullName.Substring($prefix).Split([char[]]@('\\','/'))\n\
           $skip = $false\n\
           foreach ($seg in $segments) {{\n\
             foreach ($e in $excludes) {{ if ($seg -like $e) {{ $skip = $true; break }} }}\n\
             if ($skip) {{ break }}\n\
           }}\n\
           -not $skip\n\
         }} | ForEach-Object {{\n\
           $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash\n\
           $rel = $_.FullName.Substring($prefix).Replace('\\','/')\n\
           \"$hash  $rel\"\n\
         }}",
        root = ps_single_quote(root),
        excludes = ps_string_array(name_only_excludes)
    );
    format!(
        "powershell -NoProfile -EncodedCommand {}",
        powershell_encoded_command(&script)
    )
}

/// Windows counterpart of [`remote_paths_walk_command_safe`]: PowerShell
/// recursive enumeration that emits one relpath per line — no hashing,
/// since the hook gate only needs to know which paths would be touched.
pub fn remote_paths_walk_command_safe_windows(root: &str, name_only_excludes: &[String]) -> String {
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()\n\
         $root = '{root}'\n\
         if (-not (Test-Path -LiteralPath $root -PathType Container)) {{ return }}\n\
         $rootAbs = (Resolve-Path -LiteralPath $root).Path\n\
         $excludes = @({excludes})\n\
         $prefix = $rootAbs.TrimEnd('\\').Length + 1\n\
         Get-ChildItem -LiteralPath $rootAbs -File -Recurse -Force | Where-Object {{\n\
           $segments = $_.FullName.Substring($prefix).Split([char[]]@('\\','/'))\n\
           $skip = $false\n\
           foreach ($seg in $segments) {{\n\
             foreach ($e in $excludes) {{ if ($seg -like $e) {{ $skip = $true; break }} }}\n\
             if ($skip) {{ break }}\n\
           }}\n\
           -not $skip\n\
         }} | ForEach-Object {{ $_.FullName.Substring($prefix).Replace('\\','/') }}",
        root = ps_single_quote(root),
        excludes = ps_string_array(name_only_excludes)
    );
    format!(
        "powershell -NoProfile -EncodedCommand {}",
        powershell_encoded_command(&script)
    )
}

/// Parse the PowerShell walk-output (one path per line, separated by
/// CR/LF) into a path set. Compatible with the POSIX
/// [`parse_paths_walk_output`] semantics: paths are joined onto
/// `base_name` and any `./` prefix is stripped.
pub fn parse_paths_walk_output_lines(text: &str, base_name: &Path) -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    for rel in text.lines() {
        let trimmed = rel.trim();
        if trimmed.is_empty() {
            continue;
        }
        let trimmed = trimmed.trim_start_matches("./");
        out.insert(base_name.join(trimmed));
    }
    out
}

/// Escape a string for embedding inside a PowerShell single-quoted
/// literal — single quotes are doubled, everything else is literal.
fn ps_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

/// Render a list of names as a PowerShell array literal of single-quoted
/// strings: `'a','b','c'` (or `` for an empty list).
fn ps_string_array(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("'{}'", ps_single_quote(n)))
        .collect::<Vec<_>>()
        .join(",")
}

/// Encode a PowerShell script for `-EncodedCommand`: UTF-16 LE, then
/// base64. Skips all of the cmd.exe quoting interactions that make
/// inline `-Command "..."` so fragile when the script contains paths
/// and array literals.
fn powershell_encoded_command(script: &str) -> String {
    use base64::engine::Engine;
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for u in utf16 {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Parse the NUL-separated `find -print0` output into a path set.
pub fn parse_paths_walk_output(text: &str, base_name: &Path) -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    for rel in text.split('\0') {
        if rel.is_empty() {
            continue;
        }
        let trimmed = rel.trim_start_matches("./");
        out.insert(base_name.join(trimmed));
    }
    out
}

/// Compute a path-only change set: two `Path` sets in, one classified list
/// out. Used by the hook gate, which only needs the per-entry op for
/// policy evaluation, not the eventual `Skip`-vs-`Update` distinction.
pub fn compute_paths(
    source: &HashSet<PathBuf>,
    dest: &HashSet<PathBuf>,
    mirror: bool,
) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::with_capacity(source.len());
    for rel in source {
        let op = if dest.contains(rel) {
            ChangeOp::Update
        } else {
            ChangeOp::Create
        };
        entries.push(Entry {
            op,
            rel_path: rel.clone(),
        });
    }
    if mirror {
        for rel in dest {
            if !source.contains(rel) {
                entries.push(Entry {
                    op: ChangeOp::Delete,
                    rel_path: rel.clone(),
                });
            }
        }
    }
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    entries
}

/// Hash a single file with sha-256. Read into a small buffer so even very
/// large files stay bounded in memory.
pub fn hash_file(path: &Path) -> Result<Hash> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Build the remote shell command that lists `(hex_hash, rel_path)` lines
/// for every regular file under `root`, pruning any directory matching a
/// name-only exclude pattern. Patterns containing a `/` or shell-glob
/// metacharacters beyond `*?[` are left to a post-walk filter.
///
/// The command picks `sha256sum` (Linux) or falls back to `shasum -a 256`
/// (macOS), so the engine works against either family of remote host.
pub fn remote_walk_command(root: &str, name_only_excludes: &[String]) -> String {
    let mut cmd = format!("cd {} && find . ", shell_quote(root));
    if !name_only_excludes.is_empty() {
        cmd.push_str("\\( ");
        for (i, pat) in name_only_excludes.iter().enumerate() {
            if i > 0 {
                cmd.push_str(" -o ");
            }
            cmd.push_str(&format!("-name {}", shell_quote(pat)));
        }
        cmd.push_str(" \\) -prune -o ");
    }
    cmd.push_str(
        "-type f -print0 | xargs -0 sh -c 'if command -v sha256sum >/dev/null 2>&1; \
         then sha256sum -- \"$@\"; else shasum -a 256 -- \"$@\"; fi' sh",
    );
    cmd
}

/// Parse `<hex_hash>  <relative_path>` output, one entry per line, into the
/// engine's `HashMap`. Paths are relative to the walk root (stripped of any
/// leading `./`). `sha256sum` outputs `<64 hex>  <path>\n`; `shasum -a 256`
/// uses the same shape on macOS.
pub fn parse_walk_output(text: &str, base_name: &Path) -> Result<HashMap<PathBuf, Hash>> {
    let mut out = HashMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        // Hash, then two spaces, then path. Some shasum builds emit `*` as
        // the binary-mode marker between the spaces; handle both.
        let (hash_hex, rest) = line
            .split_once("  ")
            .or_else(|| line.split_once(" *"))
            .ok_or_else(|| anyhow::anyhow!("malformed sha line: {line:?}"))?;
        if hash_hex.len() != 64 {
            bail!("unexpected hash width on line: {line:?}");
        }
        let mut hash = [0u8; 32];
        for (i, byte) in hash.iter_mut().enumerate() {
            let pair = &hash_hex[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(pair, 16).with_context(|| format!("non-hex in {line:?}"))?;
        }
        let rel = rest.trim_start_matches("./");
        let rel = base_name.join(rel);
        out.insert(rel, hash);
    }
    Ok(out)
}

/// Partition exclude patterns into those find can prune (no `/`) and those
/// the engine post-filters in-process.
pub fn partition_excludes(patterns: &[String]) -> (Vec<String>, Vec<String>) {
    let mut name_only = Vec::new();
    let mut complex = Vec::new();
    for pat in patterns {
        if pat.contains('/') {
            complex.push(pat.clone());
        } else {
            name_only.push(pat.clone());
        }
    }
    (name_only, complex)
}

/// Quote a string as a single POSIX shell word.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// A type-erased pair of timeout values for use by callers that bundle a
/// transfer's various deadlines. The engine itself only needs one.
#[allow(dead_code)]
pub fn _timeout_marker(_d: Duration) {}

/// OS-aware dispatch for the walk command builders and the paths-walk
/// output parser. Mirrors the same pattern used in `ssh::transfer`: each
/// caller (`pool::sync_*`, `control::sync_gate`) writes
/// `os.walk_command_with_hashes(...)` instead of a `match` over
/// `RemoteOs::Posix`/`Windows`, so adding a third remote family means
/// adding new variants here, not chasing call sites across the codebase.
impl crate::ssh::RemoteOs {
    /// Build the walk command that produces `<sha256>  <relpath>` lines —
    /// used by `sync_get` / `sync_put` to know which files to skip on a
    /// hash match. `parse_walk_output` consumes the result; both POSIX
    /// and Windows walk scripts emit the same line format, so the parser
    /// is OS-neutral.
    pub fn walk_command_with_hashes(self, root: &str, name_only_excludes: &[String]) -> String {
        match self {
            crate::ssh::RemoteOs::Posix => remote_walk_command_safe(root, name_only_excludes),
            crate::ssh::RemoteOs::Windows => {
                remote_walk_command_safe_windows(root, name_only_excludes)
            }
        }
    }

    /// Build the walk command that produces only relative paths — used by
    /// the sync policy gate, which only needs to know which paths a
    /// transfer would touch (no content). Pair with `parse_paths_walk`.
    pub fn paths_walk_command(self, root: &str, name_only_excludes: &[String]) -> String {
        match self {
            crate::ssh::RemoteOs::Posix => remote_paths_walk_command_safe(root, name_only_excludes),
            crate::ssh::RemoteOs::Windows => {
                remote_paths_walk_command_safe_windows(root, name_only_excludes)
            }
        }
    }

    /// Parse the output of [`paths_walk_command`] into a set of relative
    /// paths. The two scripts emit different shapes (POSIX = `find -print0`
    /// NUL-separated, Windows = one path per line), so the parser is
    /// OS-aware too.
    pub fn parse_paths_walk(self, text: &str, base_name: &Path) -> HashSet<PathBuf> {
        match self {
            crate::ssh::RemoteOs::Posix => parse_paths_walk_output(text, base_name),
            crate::ssh::RemoteOs::Windows => parse_paths_walk_output_lines(text, base_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn h(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn compute_classifies_each_entry() {
        let mut src = HashMap::new();
        src.insert(PathBuf::from("a"), h(1));
        src.insert(PathBuf::from("b"), h(2));
        src.insert(PathBuf::from("c"), h(3));

        let mut dst = HashMap::new();
        dst.insert(PathBuf::from("a"), h(1)); // skip
        dst.insert(PathBuf::from("b"), h(9)); // update
        dst.insert(PathBuf::from("d"), h(4)); // delete (mirror only)

        let mirror = compute(src.clone(), dst.clone(), true);
        let counts = mirror.counts();
        assert_eq!(counts.created, 1); // c
        assert_eq!(counts.updated, 1); // b
        assert_eq!(counts.skipped, 1); // a
        assert_eq!(counts.deleted, 1); // d

        let additive = compute(src, dst, false);
        let counts = additive.counts();
        assert_eq!(counts.created, 1);
        assert_eq!(counts.updated, 1);
        assert_eq!(counts.skipped, 1);
        assert_eq!(counts.deleted, 0); // additive omits the d entry
    }

    #[test]
    fn walk_local_returns_an_empty_map_for_a_missing_root() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("nope");
        let listing = walk_local(&absent, Path::new("nope"), &GlobSet::empty()).unwrap();
        assert!(listing.is_empty());
    }

    #[test]
    fn walk_local_hashes_a_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("solo.txt");
        std::fs::write(&path, b"data").unwrap();
        let listing = walk_local(&path, Path::new("solo.txt"), &GlobSet::empty()).unwrap();
        assert_eq!(listing.len(), 1);
        assert!(listing.contains_key(&PathBuf::from("solo.txt")));
    }

    #[test]
    fn walk_local_descends_a_directory_and_respects_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("keep.rs"), b"src").unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::write(root.join("target").join("artifact"), b"x").unwrap();

        let excludes = compile_excludes(&["target".into()]).unwrap();
        let listing = walk_local(&root, Path::new("proj"), &excludes).unwrap();

        assert!(listing.contains_key(&PathBuf::from("proj/keep.rs")));
        assert!(!listing.contains_key(&PathBuf::from("proj/target/artifact")));
    }

    #[test]
    fn parse_walk_output_handles_sha256sum_and_shasum_shapes() {
        let zero = "0".repeat(64);
        let one = "1".repeat(64);
        // sha256sum two-space form, shasum binary-marker form, and a
        // leading-./ prefix that walks of `.` always produce.
        let text = format!("{zero}  ./first.txt\n{one} *sub/second.bin\n");
        let parsed = parse_walk_output(&text, Path::new("proj")).unwrap();
        assert!(parsed.contains_key(&PathBuf::from("proj/first.txt")));
        assert!(parsed.contains_key(&PathBuf::from("proj/sub/second.bin")));
    }

    #[test]
    fn partition_excludes_splits_on_slash() {
        let (name_only, complex) =
            partition_excludes(&["target".into(), "src/local.rs".into(), "*.log".into()]);
        assert_eq!(name_only, vec!["target".to_string(), "*.log".to_string()]);
        assert_eq!(complex, vec!["src/local.rs".to_string()]);
    }
}
