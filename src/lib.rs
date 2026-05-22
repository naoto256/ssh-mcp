//! Policy-gated SSH execution MCP server.
//!
//! Enforcement lives outside the model: the model only picks a host and a
//! command; whether that command runs is decided by the hook proxy and the
//! daemon's policy evaluator.

pub mod audit;
pub mod config;
pub mod control;
pub mod daemon;
pub mod hook;
pub mod mcp;
pub mod paths;
pub mod policy;
pub mod serve;
pub mod ssh;
