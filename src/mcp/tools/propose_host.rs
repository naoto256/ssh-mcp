//! `propose_host` body — write a pending host entry to the ephemeral TOML.
//!
//! The tool's whole reason to exist is to let Claude *propose* an ephemeral
//! host (typically a freshly spun-up cloud VM) without giving the model the
//! ability to *activate* one. Every entry is written with `disabled = true`
//! and the user must hand-edit the TOML to flip it; that hand edit is the
//! trust gate. The tool also picks the alias and hard-codes `policy =
//! ["claude"]` so neither can be smuggled in via the input.
//!
//! Side effects are strictly file-only — the daemon's in-memory state is
//! untouched. The new entry surfaces on the next `HostsConfig::load`, i.e.
//! the next time any tool that consults the inventory is called.
//!
//! Expired and `disabled = true` entries are pruned/skipped centrally inside
//! `HostsConfig::load`; this module does not need to know about that.

use std::io::Write;
use std::path::Path;

use jiff::{SignedDuration, Timestamp};
use rand::Rng;
use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use russh::keys::ssh_key;
use toml_edit::{Array, DocumentMut, Item, Table, Value, value};

use crate::config::{HostsConfig, ephemeral_file_for};
use crate::mcp::SshMcpServer;
use crate::mcp::types::{ProposeHostParams, ProposeHostResult};

/// Maximum allowed gap between "now" and `expires_at`. Keeps the inventory
/// from accumulating year-long pending entries — anything that needs to live
/// longer should be promoted to a normal entry by hand.
const MAX_EXPIRES_HORIZON: SignedDuration = SignedDuration::from_hours(24 * 30);

/// How many tries we make to draw a random alias that does not collide. The
/// 6-hex-char space is 16M; ten tries is overkill but cheap.
const ALIAS_RETRIES: usize = 10;

pub(in crate::mcp) async fn handle(
    server: &SshMcpServer,
    params: Parameters<ProposeHostParams>,
) -> Result<Json<ProposeHostResult>, String> {
    let params = params.0;
    let plan = validate(&params, &server.config_path)?;
    let ephem_path = ephemeral_file_for(&server.config_path);
    let snippet = write_entry(&ephem_path, &plan)?;
    Ok(Json(ProposeHostResult {
        status: "proposed".into(),
        alias: plan.alias.clone(),
        config_path: ephem_path.display().to_string(),
        snippet,
        activate_hint: format!(
            "Remove `disabled = true` from [hosts.{}] in {} (or set it to false) to enable.",
            plan.alias,
            ephem_path.display()
        ),
        expires_at: plan.expires_at.to_string(),
    }))
}

/// A validated proposal, ready to write.
struct Plan {
    alias: String,
    hostname: String,
    user: String,
    port: u16,
    purpose: String,
    tags: Vec<String>,
    proxy_jump: Vec<String>,
    expires_at: Timestamp,
    /// OpenSSH-formatted pinned host key, already validated as parseable.
    host_key: String,
}

fn validate(params: &ProposeHostParams, config_path: &Path) -> Result<Plan, String> {
    let hostname = params.hostname.trim();
    if hostname.is_empty() {
        return Err("hostname must not be empty".into());
    }
    // Cheap sanity check: hostnames and IP literals are made of ASCII
    // alnum, `.`, `:`, `-`, `_`, `[`, `]`. Reject anything that's clearly
    // a stray field (spaces, quotes, control chars) before it lands in the
    // TOML. Real DNS/IP validation lives one layer down at connect time.
    if hostname.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '"' | '\'' | '\\' | '/' | '\n' | '\r' | '\t')
    }) {
        return Err(format!("hostname {hostname:?} contains illegal characters"));
    }

    let user = params.user.trim();
    if user.is_empty() {
        return Err("user must not be empty".into());
    }

    let purpose = params.purpose.trim();
    if purpose.is_empty() {
        return Err("purpose must not be empty".into());
    }

    let port = params.port.unwrap_or(22);
    if port == 0 {
        return Err("port must be between 1 and 65535".into());
    }

    let expires_at: Timestamp = params
        .expires_at
        .parse()
        .map_err(|e| format!("expires_at is not a valid RFC 3339 timestamp: {e}"))?;
    let now = Timestamp::now();
    if expires_at <= now {
        return Err("expires_at must be in the future".into());
    }
    if expires_at.duration_since(now) > MAX_EXPIRES_HORIZON {
        return Err("expires_at must be no more than 30 days from now".into());
    }

    // Tags: drop empties / whitespace-only.
    let tags: Vec<String> = params
        .tags
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    // proxy_jump aliases must resolve to active hosts. `HostsConfig::load`
    // already filters out disabled / expired entries, so this naturally
    // rejects chains through pending ones.
    let config =
        HostsConfig::load(config_path).map_err(|e| format!("loading existing config: {e:#}"))?;
    let mut proxy_jump = Vec::with_capacity(params.proxy_jump.len());
    for hop in &params.proxy_jump {
        let hop = hop.trim();
        if hop.is_empty() {
            return Err("proxy_jump entries must not be empty".into());
        }
        if config.host(hop).is_none() {
            return Err(format!("proxy_jump host {hop:?} is not an active host"));
        }
        proxy_jump.push(hop.to_string());
    }

    // Pinned host key. Only the OpenSSH-format parseability is checked here;
    // matching against the live server key happens at connect time in
    // `StrictHostKey::check_server_key`.
    let host_key = {
        let trimmed = params.host_key.trim();
        if trimmed.is_empty() {
            return Err("host_key must not be empty".into());
        }
        ssh_key::PublicKey::from_openssh(trimmed)
            .map_err(|e| format!("host_key is not a valid OpenSSH public key: {e}"))?;
        trimmed.to_string()
    };

    let alias = pick_alias(config_path)?;

    Ok(Plan {
        alias,
        hostname: hostname.to_string(),
        user: user.to_string(),
        port,
        purpose: purpose.to_string(),
        tags,
        proxy_jump,
        expires_at,
        host_key,
    })
}

/// Draw a `tmp-XXXXXX` alias that does not collide with any entry currently
/// in the TOML — active, disabled, or expired-but-not-yet-GC'd. The check is
/// done against the raw TOML, not against `HostsConfig::load`, because a
/// disabled/expired entry is still a name that lives in the file and would
/// produce a duplicate-table error if reused.
fn pick_alias(config_path: &Path) -> Result<String, String> {
    let existing = existing_aliases_for_inventory(config_path)?;
    let mut rng = rand::rng();
    for _ in 0..ALIAS_RETRIES {
        let n: u32 = rng.random_range(0..0x0100_0000);
        let alias = format!("tmp-{n:06x}");
        if !existing.contains(&alias) {
            return Ok(alias);
        }
    }
    Err("could not draw a unique alias after several attempts".into())
}

fn existing_aliases_for_inventory(
    config_path: &Path,
) -> Result<std::collections::HashSet<String>, String> {
    let mut existing = existing_aliases(config_path)?;
    existing.extend(existing_aliases(&ephemeral_file_for(config_path))?);
    Ok(existing)
}

/// Aliases currently present under `[hosts.*]`. Read via `toml_edit` so a
/// disabled entry is still seen — `HostsConfig::load` would drop it.
fn existing_aliases(config_path: &Path) -> Result<std::collections::HashSet<String>, String> {
    let text = match std::fs::read_to_string(config_path) {
        Ok(t) => t,
        // A missing file means no aliases yet; the writer creates one.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(format!("reading {}: {e}", config_path.display())),
    };
    let doc: DocumentMut = text
        .parse()
        .map_err(|e| format!("parsing {}: {e}", config_path.display()))?;
    let mut out = std::collections::HashSet::new();
    if let Some(hosts) = doc.get("hosts").and_then(|item| item.as_table()) {
        for (k, _) in hosts.iter() {
            out.insert(k.to_string());
        }
    }
    Ok(out)
}

/// Append the validated `Plan` to the ephemeral TOML. Returns the textual
/// snippet that was added (for echoing in the result).
fn write_entry(ephem_path: &Path, plan: &Plan) -> Result<String, String> {
    let text = match std::fs::read_to_string(ephem_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("reading {}: {e}", ephem_path.display())),
    };
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|e| format!("parsing {}: {e}", ephem_path.display()))?;

    // Build the new table.
    let mut table = Table::new();
    table.set_implicit(false);
    table["hostname"] = value(plan.hostname.clone());
    table["user"] = value(plan.user.clone());
    table["port"] = value(plan.port as i64);
    table["purpose"] = value(plan.purpose.clone());
    if !plan.tags.is_empty() {
        let mut arr = Array::new();
        for t in &plan.tags {
            arr.push(Value::from(t.clone()));
        }
        table["tags"] = Item::Value(Value::Array(arr));
    }
    if !plan.proxy_jump.is_empty() {
        let mut arr = Array::new();
        for h in &plan.proxy_jump {
            arr.push(Value::from(h.clone()));
        }
        table["proxy_jump"] = Item::Value(Value::Array(arr));
    }
    // Hard-coded; never sourced from the model.
    let mut policy = Array::new();
    policy.push(Value::from("claude"));
    let mut policy_item = Item::Value(Value::Array(policy));
    // Trailing comment to flag the policy line as adjustable.
    if let Some(v) = policy_item.as_value_mut() {
        v.decor_mut().set_suffix(
            "  # adjust to a stricter gate if `claude` is too permissive for this host",
        );
    }
    table["policy"] = policy_item;
    // `expires_at` written as a native TOML datetime (jiff stringifies to
    // RFC 3339, which toml_edit accepts for `toml_edit::Datetime`).
    let ts_str = plan.expires_at.to_string();
    let dt: toml_edit::Datetime = ts_str
        .parse()
        .map_err(|e| format!("internal: serializing expires_at: {e}"))?;
    table["expires_at"] = value(dt);
    // Pinned host key. Lives between `expires_at` and `disabled` so a reader
    // sees the activation comment last.
    table["host_key"] = value(plan.host_key.clone());
    // Activation gate. The trailing comment is what the user actually reads
    // when they open the file — keep it on this line.
    let mut disabled_item = value(true);
    if let Some(v) = disabled_item.as_value_mut() {
        v.decor_mut()
            .set_suffix("  # remove this line (or set to false) to activate");
    }
    table["disabled"] = disabled_item;

    // Insert into doc.hosts.
    let hosts = doc
        .entry("hosts")
        .or_insert_with(|| {
            Item::Table({
                let mut t = Table::new();
                t.set_implicit(true);
                t
            })
        })
        .as_table_mut()
        .ok_or_else(|| "config root `hosts` is not a table".to_string())?;
    if hosts.contains_key(&plan.alias) {
        // pick_alias already guarded against this; treat as a bug.
        return Err(format!(
            "internal: alias {} collided despite the retry loop",
            plan.alias
        ));
    }
    hosts.insert(&plan.alias, Item::Table(table));

    // Render the new doc and the snippet for that one entry.
    let new_text = doc.to_string();

    // Snippet: re-render just the inserted table by extracting it from the
    // freshly serialized doc.
    let snippet = extract_snippet(&new_text, &plan.alias).unwrap_or_default();

    let dir = ephem_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("creating temp file in {}: {e}", dir.display()))?;
    tmp.write_all(new_text.as_bytes())
        .map_err(|e| format!("writing config: {e}"))?;
    tmp.persist(ephem_path)
        .map_err(|e| format!("replacing {}: {e}", ephem_path.display()))?;
    Ok(snippet)
}

/// Pull out the `[hosts.<alias>]` block (up to but not including the next
/// section header) from a rendered TOML string. The whole doc has to be re-
/// rendered first so we know exactly what formatting `toml_edit` chose.
fn extract_snippet(text: &str, alias: &str) -> Option<String> {
    let header = format!("[hosts.{alias}]");
    let start = text.find(&header)?;
    let after = &text[start..];
    // Find the next line that starts with `[` (a new section) after the
    // first character — that's the end of our block.
    let mut end_rel = after.len();
    let mut i = 0;
    for line in after.split_inclusive('\n') {
        if i > 0 && line.trim_start().starts_with('[') {
            end_rel = i;
            break;
        }
        i += line.len();
    }
    Some(after[..end_rel].trim_end_matches('\n').to_string() + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(hostname: &str, user: &str, purpose: &str, expires_at: &str) -> ProposeHostParams {
        ProposeHostParams {
            hostname: hostname.into(),
            user: user.into(),
            purpose: purpose.into(),
            expires_at: expires_at.into(),
            port: None,
            tags: vec![],
            proxy_jump: vec![],
            host_key: VALID_HOST_KEY.into(),
        }
    }

    /// A real, parseable ed25519 public key. Reused across tests as the
    /// default `host_key` injected by the `params` helper. Generated from a
    /// throwaway keypair — never used to auth anywhere.
    const VALID_HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDUPtEBVQ314blItt/QQgFgNvrPgU/eEZY1b6kj9IgiF test@example";

    fn future_iso(days: i64) -> String {
        let t = Timestamp::now() + SignedDuration::from_hours(24 * days);
        t.to_string()
    }

    fn fresh_config(dir: &Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("ssh-hosts.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn rejects_an_invalid_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let mut p = params("10.0.0.1", "ubuntu", "scratch", &future_iso(1));
        p.port = Some(0);
        assert!(validate(&p, &path).is_err());
    }

    #[test]
    fn rejects_a_past_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let p = params("10.0.0.1", "ubuntu", "scratch", "2000-01-01T00:00:00Z");
        assert!(validate(&p, &path).is_err());
    }

    #[test]
    fn rejects_an_expiry_more_than_30_days_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let p = params("10.0.0.1", "ubuntu", "scratch", &future_iso(40));
        assert!(validate(&p, &path).is_err());
    }

    #[test]
    fn rejects_a_garbled_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let p = params("not a host", "ubuntu", "scratch", &future_iso(1));
        assert!(validate(&p, &path).is_err());
    }

    #[test]
    fn rejects_an_empty_purpose() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let p = params("10.0.0.1", "ubuntu", "   ", &future_iso(1));
        assert!(validate(&p, &path).is_err());
    }

    #[test]
    fn rejects_a_proxy_jump_that_is_not_in_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let mut p = params("10.0.0.1", "ubuntu", "scratch", &future_iso(1));
        p.proxy_jump = vec!["ghost".into()];
        assert!(validate(&p, &path).is_err());
    }

    #[test]
    fn accepts_a_proxy_jump_that_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(
            dir.path(),
            r#"
[hosts.bastion]
hostname = "1.2.3.4"
purpose = "jump"
policy = ["free"]
"#,
        );
        let mut p = params("10.0.0.1", "ubuntu", "scratch", &future_iso(1));
        p.proxy_jump = vec!["bastion".into()];
        validate(&p, &path).unwrap();
    }

    #[test]
    fn writes_a_pending_entry_and_preserves_existing_layout() {
        let dir = tempfile::tempdir().unwrap();
        let original = r#"# user's notes — must survive
[hosts.live]
hostname = "10.0.0.99"
purpose = "main box"  # inline comment
policy = ["free"]
"#;
        let path = fresh_config(dir.path(), original);
        let p = params("13.0.0.1", "ubuntu", "azure scratch", &future_iso(1));
        let plan = validate(&p, &path).unwrap();
        let ephem_path = ephemeral_file_for(&path);
        let snippet = write_entry(&ephem_path, &plan).unwrap();

        // The main file is daemon read-only and must not change.
        let main_after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(main_after, original);
        // The new entry must be present in the ephemeral file.
        let ephem_after = std::fs::read_to_string(&ephem_path).unwrap();
        let header = format!("[hosts.{}]", plan.alias);
        assert!(ephem_after.contains(&header));
        assert!(ephem_after.contains("disabled = true"));
        assert!(ephem_after.contains("# remove this line"));
        assert!(ephem_after.contains(r#"policy = ["claude"]"#));
        // Snippet must echo the new block.
        assert!(snippet.contains(&header));
        assert!(snippet.contains("disabled = true"));
    }

    #[test]
    fn rejects_a_garbled_host_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let mut p = params("10.0.0.1", "ubuntu", "scratch", &future_iso(1));
        p.host_key = "not a key".into();
        assert!(validate(&p, &path).is_err());
    }

    #[test]
    fn rejects_an_empty_host_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let mut p = params("10.0.0.1", "ubuntu", "scratch", &future_iso(1));
        p.host_key = "   ".into();
        assert!(validate(&p, &path).is_err());
    }

    #[test]
    fn writes_the_host_key_between_expires_at_and_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        let p = params("10.0.0.1", "ubuntu", "scratch", &future_iso(1));
        let plan = validate(&p, &path).unwrap();
        assert_eq!(plan.host_key, VALID_HOST_KEY);
        let snippet = write_entry(&ephemeral_file_for(&path), &plan).unwrap();
        assert!(snippet.contains("host_key = "));
        assert!(snippet.contains(VALID_HOST_KEY));
        let hk_pos = snippet.find("host_key").unwrap();
        let dis_pos = snippet.find("disabled").unwrap();
        assert!(hk_pos < dis_pos, "host_key must precede disabled");
    }

    #[test]
    fn alias_collision_retry() {
        // Pre-populate the config with every tmp- alias the random draw
        // could possibly land on for a tightly seeded space. Easier
        // approach: insert a single alias and confirm pick_alias does not
        // return it. (Full collision exercise would require seeding RNG.)
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(
            dir.path(),
            r#"
[hosts.tmp-000000]
hostname = "1.1.1.1"
purpose = "decoy"
policy = ["claude"]
disabled = true
"#,
        );
        // Run many draws; none should match the pre-seeded alias.
        for _ in 0..50 {
            let a = pick_alias(&path).unwrap();
            assert_ne!(a, "tmp-000000");
            assert!(a.starts_with("tmp-"));
            assert_eq!(a.len(), 10);
        }
    }

    #[test]
    fn alias_collision_checks_ephemeral_file_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_config(dir.path(), "");
        std::fs::write(
            ephemeral_file_for(&path),
            r#"
[hosts.tmp-000000]
hostname = "1.1.1.1"
purpose = "decoy"
policy = ["claude"]
disabled = true
"#,
        )
        .unwrap();

        for _ in 0..50 {
            let a = pick_alias(&path).unwrap();
            assert_ne!(a, "tmp-000000");
            assert!(a.starts_with("tmp-"));
            assert_eq!(a.len(), 10);
        }
    }
}
