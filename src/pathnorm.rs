//! Lexical path normalization for transfer paths.
//!
//! A transfer path is checked by the policy gate and then used by the transfer
//! itself, in two separate code paths. Both normalize the path the same way
//! here, so a `..` component cannot make the gate see one path while the
//! transfer touches another.

use std::path::PathBuf;

use anyhow::{Result, bail};

/// Normalize a local transfer path: expand a leading `~`, then resolve `.` and
/// `..` lexically. The result must be absolute — the daemon has no meaningful
/// working directory, so a relative local path is rejected.
pub fn normalize_local(path: &str) -> Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let expanded = expand_home(path.trim(), &home);
    if !expanded.starts_with('/') {
        bail!("the local path {path:?} must be absolute or start with ~/");
    }
    Ok(PathBuf::from(resolve(&expanded)))
}

/// Normalize a remote transfer path: resolve `.` and `..` lexically. A leading
/// `~` is rejected — it is not the daemon's home, and the remote `tar`/`rsync`
/// invocations do not expand it; a remote path is absolute or relative to the
/// login directory.
pub fn normalize_remote(path: &str) -> Result<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        bail!("the remote path is empty");
    }
    if trimmed.starts_with('~') {
        bail!(
            "the remote path {path:?} must be absolute or relative to the home \
             directory, without a leading ~"
        );
    }
    Ok(resolve(trimmed))
}

/// Expand a leading `~` or `~/` against a home directory.
fn expand_home(path: &str, home: &str) -> String {
    if home.is_empty() {
        return path.to_string();
    }
    if path == "~" {
        home.to_string()
    } else if let Some(rest) = path.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        path.to_string()
    }
}

/// Collapse `.` and `..` components without touching the filesystem.
fn resolve(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => match out.last() {
                Some(&last) if last != ".." => {
                    out.pop();
                }
                // A `..` at the root is dropped; one in a relative path is kept.
                _ if !absolute => out.push(".."),
                _ => {}
            },
            other => out.push(other),
        }
    }
    let joined = out.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_collapses_dot_and_dotdot() {
        assert_eq!(resolve("/a/b/../c"), "/a/c");
        assert_eq!(resolve("/a/./b"), "/a/b");
        assert_eq!(resolve("/a/b/../../c"), "/c");
        assert_eq!(resolve("/../etc"), "/etc");
        assert_eq!(resolve("a/../b"), "b");
        assert_eq!(resolve("../a/../b"), "../b");
        assert_eq!(resolve("/a//b"), "/a/b");
    }

    #[test]
    fn expand_home_handles_tilde_forms() {
        assert_eq!(expand_home("~", "/home/example"), "/home/example");
        assert_eq!(
            expand_home("~/docs/notes", "/home/example"),
            "/home/example/docs/notes"
        );
        assert_eq!(expand_home("/etc/hosts", "/home/example"), "/etc/hosts");
        // A `~user` form is not a home reference; left untouched.
        assert_eq!(expand_home("~other/x", "/home/example"), "~other/x");
    }

    #[test]
    fn normalize_remote_rejects_tilde_and_resolves_traversal() {
        assert!(normalize_remote("~/secrets").is_err());
        assert!(normalize_remote("").is_err());
        assert_eq!(
            normalize_remote("/var/log/../lib").unwrap(),
            "/var/lib".to_string()
        );
        assert_eq!(
            normalize_remote("data/app").unwrap(),
            "data/app".to_string()
        );
    }

    #[test]
    fn normalize_local_requires_an_absolute_result() {
        assert!(normalize_local("relative/path").is_err());
        assert_eq!(
            normalize_local("/tmp/a/../b").unwrap(),
            PathBuf::from("/tmp/b")
        );
    }
}
