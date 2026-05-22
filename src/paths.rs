//! Filesystem locations ssh-mcp uses.
//!
//! The config sits directly under `~/.ssh`; all daemon runtime state lives in
//! the `~/.ssh/ssh-mcp/` directory. Keeping everything under `~/.ssh` means an
//! existing `Read(~/.ssh/**)` deny rule protects it all.

use std::path::PathBuf;

use anyhow::{Context, Result};

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// The host inventory and policy file, `~/.ssh/ssh-mcp.toml`.
pub fn config_file() -> Result<PathBuf> {
    Ok(home()?.join(".ssh").join("ssh-mcp.toml"))
}

/// The strict host-key file, `~/.ssh/known_hosts`.
pub fn known_hosts() -> Result<PathBuf> {
    Ok(home()?.join(".ssh").join("known_hosts"))
}

/// The user's Claude Code settings, `~/.claude/settings.json`.
pub fn claude_settings() -> Result<PathBuf> {
    Ok(home()?.join(".claude").join("settings.json"))
}

/// The daemon's runtime directory, `~/.ssh/ssh-mcp/`.
pub fn runtime_dir() -> Result<PathBuf> {
    Ok(home()?.join(".ssh").join("ssh-mcp"))
}

/// The MCP transport socket, `~/.ssh/ssh-mcp/mcp.sock`.
pub fn mcp_socket() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("mcp.sock"))
}

/// The policy control socket, `~/.ssh/ssh-mcp/control.sock`.
pub fn control_socket() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("control.sock"))
}

/// The exec audit log, `~/.ssh/ssh-mcp/audit.jsonl`.
pub fn audit_log() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("audit.jsonl"))
}
