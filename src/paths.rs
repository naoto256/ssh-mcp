//! Filesystem locations HekateSSH uses.
//!
//! The config sits directly under `~/.ssh`; all daemon runtime state lives in
//! the `~/.ssh/hekatessh/` directory. Keeping everything under `~/.ssh` means an
//! existing `Read(~/.ssh/**)` deny rule protects it all.

use std::path::PathBuf;

use anyhow::{Context, Result};

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// The host inventory and policy file, `~/.ssh/hekatessh.toml`.
pub fn config_file() -> Result<PathBuf> {
    Ok(home()?.join(".ssh").join("hekatessh.toml"))
}

/// The strict host-key file, `~/.ssh/known_hosts`.
pub fn known_hosts() -> Result<PathBuf> {
    Ok(home()?.join(".ssh").join("known_hosts"))
}

/// The user's Claude Code settings, `~/.claude/settings.json`.
pub fn claude_settings() -> Result<PathBuf> {
    Ok(home()?.join(".claude").join("settings.json"))
}

/// The daemon's runtime directory, `~/.ssh/hekatessh/`.
pub fn runtime_dir() -> Result<PathBuf> {
    Ok(home()?.join(".ssh").join("hekatessh"))
}

/// The MCP transport socket, `~/.ssh/hekatessh/mcp.sock`.
pub fn mcp_socket() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("mcp.sock"))
}

/// The policy control socket, `~/.ssh/hekatessh/control.sock`.
pub fn control_socket() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("control.sock"))
}

/// The exec audit log, `~/.ssh/hekatessh/audit.jsonl`.
pub fn audit_log() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("audit.jsonl"))
}
