//! The `hook` subcommand: a pure proxy that relays a PreToolUse request to the
//! server and writes back the server's decision. It holds no policy logic.

/// Entry point for the hook proxy.
pub fn run() -> anyhow::Result<()> {
    Ok(())
}
