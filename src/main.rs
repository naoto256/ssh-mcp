use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "hekatessh",
    version,
    about = "Policy-gated SSH execution MCP server for Claude Code and Codex"
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
    /// Bootstrap a hekatessh.toml skeleton from ~/.ssh/config.
    Import,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Daemon => hekatessh::daemon::run(),
        Command::Serve => hekatessh::serve::run(),
        Command::Hook => hekatessh::hook::run(),
        Command::Import => hekatessh::import::run(),
    }
}
