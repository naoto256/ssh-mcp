//! The `serve` subcommand: the MCP shim the harness spawns per session.
//!
//! It speaks no MCP itself — it relays bytes both ways between the harness
//! (stdio) and the daemon (the `mcp.sock` Unix socket), so the daemon can be
//! a single resident process shared by every session.

use anyhow::{Context, Result};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::UnixStream;

/// Entry point for the MCP shim.
pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(relay())
}

async fn relay() -> Result<()> {
    let socket = crate::paths::mcp_socket()?;
    let stream = UnixStream::connect(&socket).await.with_context(|| {
        format!(
            "the ssh-mcp daemon is not reachable at {} — is it running?",
            socket.display()
        )
    })?;

    let (mut from_daemon, mut to_daemon) = stream.into_split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    // Relay until the harness closes stdin or the daemon closes the socket.
    let harness_to_daemon = async {
        copy(&mut stdin, &mut to_daemon).await?;
        to_daemon.shutdown().await
    };
    let daemon_to_harness = async {
        copy(&mut from_daemon, &mut stdout).await?;
        stdout.flush().await
    };
    tokio::try_join!(harness_to_daemon, daemon_to_harness)?;
    Ok(())
}
