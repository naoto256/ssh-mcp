//! End-to-end file-transfer tests against a real SSH host.
//!
//! Ignored by default: CI has no host to reach. Run locally with the target
//! supplied through the environment so no real host detail is committed:
//!
//!   SSH_MCP_TEST_HOST=<ip> SSH_MCP_TEST_USER=<user> \
//!     cargo test --test transfer_e2e -- --ignored
//!
//! The host must already be in `~/.ssh/known_hosts` and the SSH agent must
//! hold a key it accepts.

use std::time::Duration;

use ssh_mcp::config::HostsConfig;
use ssh_mcp::ssh::ConnectionPool;

const TIMEOUT: Duration = Duration::from_secs(60);

/// A one-host inventory built from the environment, so the real host's
/// address and user never appear in committed source.
fn test_config() -> HostsConfig {
    let host = std::env::var("SSH_MCP_TEST_HOST").expect("set SSH_MCP_TEST_HOST");
    let mut toml =
        format!("[hosts.target]\nhostname = \"{host}\"\npurpose = \"e2e\"\npolicy = [\"free\"]\n");
    if let Ok(user) = std::env::var("SSH_MCP_TEST_USER") {
        toml.push_str(&format!("user = \"{user}\"\n"));
    }
    HostsConfig::parse(&toml).expect("generated test config should parse")
}

/// A unique remote path under `/tmp`, so concurrent runs do not collide.
fn remote_path(label: &str) -> String {
    format!("/tmp/ssh-mcp-e2e-{label}-{}", std::process::id())
}

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn round_trips_a_file() {
    let config = test_config();
    let pool = ConnectionPool::new().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let source = dir.path().join("upload.bin");
    let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    std::fs::write(&source, &payload).unwrap();
    let remote = remote_path("file");

    pool.put_file(&config, "target", &source, &remote, &[], TIMEOUT)
        .await
        .expect("upload should succeed");

    let downloaded = dir.path().join("download.bin");
    pool.get_file(&config, "target", &remote, &downloaded, &[], TIMEOUT)
        .await
        .expect("download should succeed");

    assert_eq!(std::fs::read(&downloaded).unwrap(), payload);
    pool.exec(&config, "target", &format!("rm -rf {remote}"), TIMEOUT)
        .await
        .ok();
}

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn round_trips_a_directory() {
    let config = test_config();
    let pool = ConnectionPool::new().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let source = dir.path().join("tree");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("a.txt"), b"alpha").unwrap();
    std::fs::create_dir(source.join("sub")).unwrap();
    std::fs::write(source.join("sub").join("b.txt"), b"bravo").unwrap();
    let remote = remote_path("dir");

    pool.put_file(&config, "target", &source, &remote, &[], TIMEOUT)
        .await
        .expect("directory upload should succeed");

    let result = dir.path().join("result");
    pool.get_file(&config, "target", &remote, &result, &[], TIMEOUT)
        .await
        .expect("directory download should succeed");

    assert_eq!(std::fs::read(result.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(
        std::fs::read(result.join("sub").join("b.txt")).unwrap(),
        b"bravo"
    );
    pool.exec(&config, "target", &format!("rm -rf {remote}"), TIMEOUT)
        .await
        .ok();
}

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn get_file_replaces_an_existing_local_path() {
    let config = test_config();
    let pool = ConnectionPool::new().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let source = dir.path().join("source.txt");
    std::fs::write(&source, b"current").unwrap();
    let remote = remote_path("replace");
    pool.put_file(&config, "target", &source, &remote, &[], TIMEOUT)
        .await
        .expect("upload should succeed");

    let destination = dir.path().join("destination.txt");
    std::fs::write(&destination, b"stale").unwrap();
    pool.get_file(&config, "target", &remote, &destination, &[], TIMEOUT)
        .await
        .expect("download onto an existing path should succeed");

    assert_eq!(std::fs::read(&destination).unwrap(), b"current");
    pool.exec(&config, "target", &format!("rm -rf {remote}"), TIMEOUT)
        .await
        .ok();
}

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn put_file_skips_excluded_entries() {
    let config = test_config();
    let pool = ConnectionPool::new().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let source = dir.path().join("project");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("keep.rs"), b"src").unwrap();
    std::fs::create_dir(source.join("skipme")).unwrap();
    std::fs::write(source.join("skipme").join("big"), b"artifact").unwrap();
    let remote = remote_path("exclude");

    pool.put_file(
        &config,
        "target",
        &source,
        &remote,
        &["skipme".to_string()],
        TIMEOUT,
    )
    .await
    .expect("upload with exclude should succeed");

    let back = dir.path().join("back");
    pool.get_file(&config, "target", &remote, &back, &[], TIMEOUT)
        .await
        .expect("download should succeed");

    assert!(back.join("keep.rs").exists());
    assert!(!back.join("skipme").exists());
    pool.exec(&config, "target", &format!("rm -rf {remote}"), TIMEOUT)
        .await
        .ok();
}
