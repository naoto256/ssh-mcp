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
    /// Run the resident daemon: the MCP server, the control socket, and the
    /// shared SSH connection pool.
    Daemon,
    /// Run the MCP shim the harness spawns per session: it relays stdio to the
    /// daemon and speaks no MCP itself.
    Serve,
    /// Run as a PreToolUse hook: a pure proxy that relays a policy query to
    /// the daemon.
    Hook,
    /// Bootstrap an ssh-mcp.toml skeleton from ~/.ssh/config.
    Import,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Daemon => ssh_mcp::daemon::run(),
        Command::Serve => ssh_mcp::serve::run(),
        Command::Hook => ssh_mcp::hook::run(),
        Command::Import => ssh_mcp::import::run(),
    }
}
