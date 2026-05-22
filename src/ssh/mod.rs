//! SSH execution: a connection pool over russh, with agent authentication,
//! strict host-key verification, and stateless per-command channels.

mod handler;
mod pool;

pub use pool::{ConnectionPool, ExecOutput};
