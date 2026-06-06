//! End-to-end tests against a real SSH host.
//!
//! Ignored by default: CI has no host to reach. Run locally with the target
//! supplied through the environment so no real host detail is committed:
//!
//!   SSH_MCP_TEST_HOST=<ip> SSH_MCP_TEST_USER=<user> \
//!     cargo test --test ssh_e2e -- --ignored
//!
//! The host must already be in `~/.ssh/known_hosts` and the SSH agent must
//! hold a key it accepts.

use std::time::Duration;

use hekatessh::config::HostsConfig;
use hekatessh::ssh::ConnectionPool;

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

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn exec_returns_stdout_and_exit_code() {
    let config = test_config();
    let pool = ConnectionPool::new().unwrap();

    let out = pool
        .exec(
            &config,
            "target",
            "echo hekatessh-ok",
            Duration::from_secs(20),
        )
        .await
        .expect("exec should succeed");

    assert_eq!(out.stdout.trim(), "hekatessh-ok");
    assert_eq!(out.stderr, "");
    assert_eq!(out.exit_code, 0);
}

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn exec_captures_stderr_and_a_nonzero_exit_code() {
    let config = test_config();
    let pool = ConnectionPool::new().unwrap();

    let out = pool
        .exec(
            &config,
            "target",
            "echo to-stderr 1>&2; exit 3",
            Duration::from_secs(20),
        )
        .await
        .expect("exec should succeed");

    assert_eq!(out.stderr.trim(), "to-stderr");
    assert_eq!(out.exit_code, 3);
}

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn exec_is_stateless_between_calls() {
    let config = test_config();
    let pool = ConnectionPool::new().unwrap();

    // A `cd` in one command must not affect the next: each exec starts fresh.
    pool.exec(&config, "target", "cd /tmp", Duration::from_secs(20))
        .await
        .expect("first exec should succeed");
    let out = pool
        .exec(&config, "target", "pwd", Duration::from_secs(20))
        .await
        .expect("second exec should succeed");

    assert_ne!(out.stdout.trim(), "/tmp");
}

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn exec_works_through_a_proxy_jump() {
    // `target` is reached by tunneling through `jump`. Both point at the same
    // host, which is enough to exercise the direct-tcpip multi-hop path.
    let host = std::env::var("SSH_MCP_TEST_HOST").expect("set SSH_MCP_TEST_HOST");
    let user_line = match std::env::var("SSH_MCP_TEST_USER") {
        Ok(user) => format!("user = \"{user}\"\n"),
        Err(_) => String::new(),
    };
    let toml = format!(
        "[hosts.jump]\nhostname = \"{host}\"\npurpose = \"jump\"\npolicy = [\"free\"]\n{user_line}\
         [hosts.target]\nhostname = \"{host}\"\npurpose = \"target\"\n\
         proxy_jump = [\"jump\"]\npolicy = [\"free\"]\n{user_line}"
    );
    let config = HostsConfig::parse(&toml).expect("generated test config should parse");
    let pool = ConnectionPool::new().unwrap();

    let out = pool
        .exec(
            &config,
            "target",
            "echo through-jump",
            Duration::from_secs(20),
        )
        .await
        .expect("exec through a proxy jump should succeed");

    assert_eq!(out.stdout.trim(), "through-jump");
    assert_eq!(out.exit_code, 0);
}

#[tokio::test]
#[ignore = "requires a reachable SSH host supplied via env vars"]
async fn exec_times_out_on_a_long_command() {
    let config = test_config();
    let pool = ConnectionPool::new().unwrap();

    let result = pool
        .exec(&config, "target", "sleep 30", Duration::from_secs(2))
        .await;

    assert!(result.is_err(), "a 30s command must exceed a 2s timeout");
}
