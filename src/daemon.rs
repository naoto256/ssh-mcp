//! The `daemon` subcommand: the resident server shared by every session.
//!
//! It owns the SSH connection pool and the host inventory, and listens on two
//! Unix sockets: `mcp.sock` for MCP sessions (one per `serve` shim) and
//! `control.sock` for policy queries (one per `hook` invocation). Both sockets
//! accept only connections from this user's own processes.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};

use crate::audit::AuditLog;
use crate::control;
use crate::mcp::SshMcpServer;
use crate::paths;
use crate::policy::Evaluator;
use crate::ssh::ConnectionPool;

/// Entry point for the daemon. Runs until the process is signalled.
pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(serve())
}

async fn serve() -> Result<()> {
    let runtime_dir = paths::runtime_dir()?;
    std::fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("creating {}", runtime_dir.display()))?;
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {}", runtime_dir.display()))?;

    let config_path = paths::config_file()?;
    let pool = Arc::new(ConnectionPool::new()?);
    let audit = AuditLog::new(paths::audit_log()?);
    let evaluator = Arc::new(Evaluator::new()?);
    let own_uid = current_uid();

    let mcp_listener = bind_socket(&paths::mcp_socket()?)?;
    let control_listener = bind_socket(&paths::control_socket()?)?;

    // Both loops run forever; if either returns it is a fatal error.
    tokio::select! {
        result = mcp_loop(mcp_listener, own_uid, pool, config_path.clone(), audit.clone()) => result,
        result = control_loop(control_listener, own_uid, evaluator, config_path, audit) => result,
    }
}

/// Remove a stale socket, bind, and restrict the new socket to the owner.
fn bind_socket(path: &Path) -> Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    Ok(listener)
}

/// This process's real user id. `getuid` cannot fail and has no side effects.
fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// Accept a connection only when its peer is one of this user's processes.
/// This backs up the directory and socket permissions with a credential check.
fn peer_is_owner(stream: &UnixStream, own_uid: u32) -> bool {
    match stream.peer_cred() {
        Ok(cred) => cred.uid() == own_uid,
        Err(_) => false,
    }
}

async fn mcp_loop(
    listener: UnixListener,
    own_uid: u32,
    pool: Arc<ConnectionPool>,
    config_path: PathBuf,
    audit: AuditLog,
) -> Result<()> {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                eprintln!("ssh-mcp: mcp socket accept failed: {e}");
                continue;
            }
        };
        if !peer_is_owner(&stream, own_uid) {
            eprintln!("ssh-mcp: rejected an mcp connection from another user");
            continue;
        }
        let server = SshMcpServer::new(pool.clone(), config_path.clone(), audit.clone());
        tokio::spawn(async move {
            if let Err(e) = server.serve_connection(stream).await {
                eprintln!("ssh-mcp: mcp session ended: {e:#}");
            }
        });
    }
}

async fn control_loop(
    listener: UnixListener,
    own_uid: u32,
    evaluator: Arc<Evaluator>,
    config_path: PathBuf,
    audit: AuditLog,
) -> Result<()> {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                eprintln!("ssh-mcp: control socket accept failed: {e}");
                continue;
            }
        };
        if !peer_is_owner(&stream, own_uid) {
            eprintln!("ssh-mcp: rejected a control connection from another user");
            continue;
        }
        let evaluator = evaluator.clone();
        let config_path = config_path.clone();
        let audit = audit.clone();
        tokio::spawn(async move {
            control::handle_connection(stream, &config_path, &evaluator, &audit).await;
        });
    }
}
