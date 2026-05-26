//! Per-tool handler bodies. Each `tools::<tool>::handle` is the actual
//! logic; the `#[tool_router]` impl block in `super::mod` keeps thin
//! delegators (`tools::<tool>::handle(self, params).await`) so the rmcp
//! macro can collect every `#[tool]` method in one place while the bodies
//! live in tool-sized files.

pub(super) mod exec;
pub(super) mod list_agent_keys;
pub(super) mod list_hosts;
pub(super) mod propose_host;
pub(super) mod trace;
pub(super) mod transfer;
