//! Bootstrap an `ssh-mcp.toml` from an existing `~/.ssh/config`.
//!
//! This is a one-time setup tool, kept out of the installed binary. Run it,
//! review the output, then save it:
//!
//!   cargo run --example import-ssh-config > ~/.ssh/ssh-mcp.toml

fn main() -> anyhow::Result<()> {
    ssh_mcp::import::run()
}
