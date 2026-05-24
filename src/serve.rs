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

    // Relay until *either* side ends. We deliberately use `select!` rather
    // than `try_join!`: when the harness (parent) dies, its end of our
    // stdin pipe is supposed to EOF — but if it crashed without flushing,
    // or the launchd-managed stdio fd lands in a half-open state, the
    // blocking `read(STDIN)` underneath `tokio::io::stdin()` can stay
    // pinned in the kernel forever (observed as `UE` ps state, unkillable
    // even by SIGKILL until the kernel unblocks the syscall). `try_join!`
    // would then wait for that doomed leg even after the daemon socket is
    // closed. With `select!`, the first side to finish drops the process,
    // which is the correct lifetime for a stdio↔socket relay: once one
    // direction is dead the other has nothing to deliver to anyway.
    tokio::select! {
        result = async {
            copy(&mut stdin, &mut to_daemon).await?;
            to_daemon.shutdown().await
        } => result?,
        result = async {
            copy(&mut from_daemon, &mut stdout).await?;
            stdout.flush().await
        } => result?,
    }
    Ok(())
}
