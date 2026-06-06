//! Bootstrap a `hekatessh.toml` skeleton from `~/.ssh/config`.
//!
//! Rather than reimplement OpenSSH's config resolution (`Host *` inheritance,
//! `Include`, `Match`), this enumerates the host aliases and asks `ssh -G` for
//! each one's fully-resolved settings — OpenSSH resolves its own format. The
//! result is printed for review, never written in place.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Read `~/.ssh/config`, resolve every host, and print an `hekatessh.toml`
/// skeleton to stdout.
pub fn run() -> Result<()> {
    let config_path = ssh_config_path()?;
    if !config_path.exists() {
        anyhow::bail!("{} does not exist", config_path.display());
    }

    let aliases = collect_aliases(&config_path);
    if aliases.is_empty() {
        anyhow::bail!("no host aliases found under {}", config_path.display());
    }

    let mut hosts = Vec::new();
    for alias in aliases {
        match resolve_host(&alias) {
            Ok(host) => hosts.push(host),
            Err(e) => eprintln!("hekatessh: skipping {alias:?}: {e:#}"),
        }
    }
    print!("{}", emit_toml(&dedup(hosts)));
    Ok(())
}

fn ssh_config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".ssh").join("config"))
}

/// A host's resolved connection settings, as reported by `ssh -G`.
#[derive(Debug, PartialEq, Eq)]
struct ResolvedHost {
    alias: String,
    hostname: String,
    user: Option<String>,
    port: Option<u16>,
    proxy_jump: Vec<String>,
}

/// The `Host` aliases and `Include` paths found in one config file.
struct Scan {
    aliases: Vec<String>,
    includes: Vec<String>,
}

/// Scan one config file's text for concrete host aliases and `Include` paths.
/// Wildcard patterns (`*`, `?`, `!`) are not concrete hosts and are skipped.
fn scan_text(text: &str) -> Scan {
    let mut aliases = Vec::new();
    let mut includes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || c == '=')
            .filter(|t| !t.is_empty())
            .collect();
        let Some((keyword, args)) = tokens.split_first() else {
            continue;
        };
        match keyword.to_ascii_lowercase().as_str() {
            "host" => {
                for &token in args {
                    if !token.contains(['*', '?', '!']) {
                        aliases.push(token.to_string());
                    }
                }
            }
            "include" => includes.extend(args.iter().map(|s| s.to_string())),
            _ => {}
        }
    }
    Scan { aliases, includes }
}

/// Walk `~/.ssh/config` and every file it `Include`s, collecting host aliases
/// in first-seen order with duplicates removed.
fn collect_aliases(config_path: &Path) -> Vec<String> {
    let mut aliases = Vec::new();
    let mut visited = HashSet::new();
    walk(config_path, &mut aliases, &mut visited);

    let mut seen = HashSet::new();
    aliases.retain(|alias| seen.insert(alias.clone()));
    aliases
}

fn walk(path: &Path, aliases: &mut Vec<String>, visited: &mut HashSet<PathBuf>) {
    let key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(key) {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let scan = scan_text(&text);
    aliases.extend(scan.aliases);
    for include in scan.includes {
        for resolved in resolve_include(&include, path) {
            walk(&resolved, aliases, visited);
        }
    }
}

/// Resolve an `Include` directive to the files it refers to. Supports a
/// `~`-prefixed path, a path relative to the including file, and a single
/// trailing `/*` directory glob.
fn resolve_include(include: &str, including_file: &Path) -> Vec<PathBuf> {
    let base = if let Some(rest) = include.strip_prefix("~/") {
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(rest),
            None => return Vec::new(),
        }
    } else if Path::new(include).is_absolute() {
        PathBuf::from(include)
    } else {
        including_file
            .parent()
            .unwrap_or(Path::new("."))
            .join(include)
    };

    if let Some(dir) = base.to_str().and_then(|s| s.strip_suffix("/*")) {
        match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .collect(),
            Err(_) => Vec::new(),
        }
    } else {
        vec![base]
    }
}

/// Ask `ssh -G` for a host's fully-resolved settings.
fn resolve_host(alias: &str) -> Result<ResolvedHost> {
    let output = std::process::Command::new("ssh")
        .arg("-G")
        .arg(alias)
        .output()
        .context("could not run `ssh -G`")?;
    if !output.status.success() {
        anyhow::bail!("`ssh -G {alias}` exited with an error");
    }
    Ok(parse_ssh_g(alias, &String::from_utf8_lossy(&output.stdout)))
}

/// Parse the `key value` lines `ssh -G` prints into a resolved host.
fn parse_ssh_g(alias: &str, output: &str) -> ResolvedHost {
    let mut hostname = alias.to_string();
    let mut user = None;
    let mut port = None;
    let mut proxy_jump = Vec::new();

    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let value = parts.collect::<Vec<_>>().join(" ");
        match key {
            "hostname" if !value.is_empty() => hostname = value,
            "user" if !value.is_empty() => user = Some(value),
            "port" => port = value.parse().ok(),
            "proxyjump" if value != "none" && !value.is_empty() => {
                proxy_jump = value.split(',').map(jump_host).collect();
            }
            _ => {}
        }
    }
    ResolvedHost {
        alias: alias.to_string(),
        hostname,
        user,
        port,
        proxy_jump,
    }
}

/// Reduce a ProxyJump entry — which may be `user@host:port` — to its host
/// alias. The jump host's own entry carries its user and port.
fn jump_host(entry: &str) -> String {
    let after_user = entry.rsplit('@').next().unwrap_or(entry);
    after_user
        .split(':')
        .next()
        .unwrap_or(after_user)
        .to_string()
}

/// Drop hosts that resolve identically to an earlier one — e.g. several
/// aliases on one `Host` line. A different user or port keeps an entry
/// distinct, since those are genuinely separate ways to reach a machine.
fn dedup(hosts: Vec<ResolvedHost>) -> Vec<ResolvedHost> {
    let mut seen = HashSet::new();
    hosts
        .into_iter()
        .filter(|h| {
            seen.insert((
                h.hostname.clone(),
                h.user.clone(),
                h.port,
                h.proxy_jump.clone(),
            ))
        })
        .collect()
}

/// Render the resolved hosts as an `hekatessh.toml` skeleton.
fn emit_toml(hosts: &[ResolvedHost]) -> String {
    let mut out = String::new();
    out.push_str("# Generated by hekatessh from ~/.ssh/config. Review before use:\n");
    out.push_str("# set each host's purpose, and its policy (claude is a safe default).\n\n");
    out.push_str(
        "# Uncomment to override the default per-command time limit (seconds):\n\
         # [defaults]\n# exec_timeout_secs = 600\n",
    );

    for host in hosts {
        out.push('\n');
        out.push_str(&format!("[hosts.{}]\n", toml_key(&host.alias)));
        out.push_str(&format!("hostname = {}\n", toml_string(&host.hostname)));
        if let Some(user) = &host.user {
            out.push_str(&format!("user     = {}\n", toml_string(user)));
        }
        if let Some(port) = host.port
            && port != 22
        {
            out.push_str(&format!("port     = {port}\n"));
        }
        if !host.proxy_jump.is_empty() {
            let list: Vec<String> = host.proxy_jump.iter().map(|j| toml_string(j)).collect();
            out.push_str(&format!("proxy_jump = [{}]\n", list.join(", ")));
        }
        out.push_str("purpose  = \"TODO: describe this host\"\n");
        out.push_str("policy   = [\"claude\"]\n");
    }
    out
}

/// A TOML table key: bare when it only uses bare-key characters, else quoted.
fn toml_key(alias: &str) -> String {
    let bare = !alias.is_empty()
        && alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare {
        alias.to_string()
    } else {
        toml_string(alias)
    }
}

/// A TOML basic string with the two characters that need escaping handled.
fn toml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_collects_concrete_aliases_and_skips_patterns() {
        let scan = scan_text(
            "Host build ci\nHost *.example.com\nHost *\n  HostName x\nInclude ~/.ssh/extra\n",
        );
        assert_eq!(scan.aliases, ["build", "ci"]);
        assert_eq!(scan.includes, ["~/.ssh/extra"]);
    }

    #[test]
    fn scan_accepts_equals_separator() {
        let scan = scan_text("Host=prod\n");
        assert_eq!(scan.aliases, ["prod"]);
    }

    #[test]
    fn parse_ssh_g_extracts_resolved_fields() {
        let output = "host build\nhostname 10.0.0.5\nuser ci\nport 2222\nproxyjump bastion\n";
        let host = parse_ssh_g("build", output);
        assert_eq!(host.hostname, "10.0.0.5");
        assert_eq!(host.user.as_deref(), Some("ci"));
        assert_eq!(host.port, Some(2222));
        assert_eq!(host.proxy_jump, ["bastion"]);
    }

    #[test]
    fn parse_ssh_g_treats_proxyjump_none_as_empty() {
        let host = parse_ssh_g("h", "hostname h\nproxyjump none\n");
        assert!(host.proxy_jump.is_empty());
    }

    #[test]
    fn jump_host_strips_user_and_port() {
        assert_eq!(jump_host("bastion"), "bastion");
        assert_eq!(jump_host("jump@bastion:2222"), "bastion");
    }

    #[test]
    fn emit_toml_renders_a_reviewable_skeleton() {
        let hosts = vec![ResolvedHost {
            alias: "build".to_string(),
            hostname: "10.0.0.5".to_string(),
            user: Some("ci".to_string()),
            port: Some(2222),
            proxy_jump: vec!["bastion".to_string()],
        }];
        let toml = emit_toml(&hosts);
        assert!(toml.contains("[hosts.build]"));
        assert!(toml.contains("hostname = \"10.0.0.5\""));
        assert!(toml.contains("port     = 2222"));
        assert!(toml.contains("proxy_jump = [\"bastion\"]"));
        assert!(toml.contains("policy   = [\"claude\"]"));
    }

    #[test]
    fn emit_toml_omits_the_default_port() {
        let hosts = vec![ResolvedHost {
            alias: "h".to_string(),
            hostname: "h".to_string(),
            user: None,
            port: Some(22),
            proxy_jump: Vec::new(),
        }];
        assert!(!emit_toml(&hosts).contains("port"));
    }

    #[test]
    fn toml_key_quotes_a_dotted_alias() {
        assert_eq!(toml_key("build"), "build");
        assert_eq!(toml_key("host.example"), "\"host.example\"");
    }

    #[test]
    fn dedup_drops_identical_hosts_but_keeps_distinct_users() {
        let host = |alias: &str, user: &str| ResolvedHost {
            alias: alias.to_string(),
            hostname: "10.0.0.5".to_string(),
            user: Some(user.to_string()),
            port: None,
            proxy_jump: Vec::new(),
        };
        // Same resolution under two aliases collapses to one.
        let collapsed = dedup(vec![host("db", "ci"), host("db.lan", "ci")]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].alias, "db");
        // A different user is a genuinely separate entry.
        let kept = dedup(vec![host("db-admin", "admin"), host("db-ro", "readonly")]);
        assert_eq!(kept.len(), 2);
    }
}
