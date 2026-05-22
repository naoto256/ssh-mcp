use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ssh-mcp",
    version,
    about = "Policy-gated SSH execution MCP server for Claude Code"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the MCP server: stdio JSON-RPC plus the policy control socket.
    Serve,
    /// Run as a PreToolUse hook: a pure proxy to the running server.
    Hook,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve => ssh_mcp::serve::run(),
        Command::Hook => ssh_mcp::hook::run(),
    }
}
