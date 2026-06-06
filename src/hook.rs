//! The `hook` subcommand: a pure proxy to the daemon's control socket.
//!
//! It forwards the PreToolUse request the harness gives it on stdin and prints
//! the daemon's decision. It holds no policy logic. It always exits 0: a
//! non-zero exit is treated by the harness as non-blocking, which would let an
//! unevaluated command run.

use std::io::{Read, Write};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The fail-closed response, emitted whenever the proxy cannot obtain a real
/// decision. Denying — rather than erroring — keeps the hook blocking.
const FAIL_CLOSED: &str = concat!(
    r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","#,
    r#""permissionDecision":"deny","#,
    r#""permissionDecisionReason":"hekatessh daemon is unreachable; failing closed"}}"#,
);

/// Entry point for the hook proxy.
pub fn run() -> anyhow::Result<()> {
    let response = relay().unwrap_or_else(|_| FAIL_CLOSED.to_string());
    print!("{response}");
    let _ = std::io::stdout().flush();
    Ok(())
}

fn relay() -> anyhow::Result<String> {
    let mut request = String::new();
    std::io::stdin().read_to_string(&mut request)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(exchange(request))?;

    // A response that is not a JSON object means the daemon misbehaved; treat
    // it as a failure so the caller falls back to the fail-closed decision.
    if !response.trim_start().starts_with('{') {
        anyhow::bail!("the daemon returned an unexpected response");
    }
    Ok(response)
}

async fn exchange(request: String) -> anyhow::Result<String> {
    let mut stream = UnixStream::connect(crate::paths::control_socket()?).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.shutdown().await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}
