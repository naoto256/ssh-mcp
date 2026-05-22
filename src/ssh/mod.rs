//! SSH execution: a connection pool over russh, with agent authentication,
//! strict host-key verification, and stateless per-command channels.

mod connect;
mod handler;
mod pool;
mod transfer;

pub use pool::{ConnectionPool, ExecOutput};
pub use transfer::TransferStats;
