//! The `serve` subcommand: the long-lived MCP server.

/// Entry point for the MCP server. Builds a Tokio runtime and runs the stdio
/// service until the client disconnects.
pub fn run() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(crate::mcp::run())
}
