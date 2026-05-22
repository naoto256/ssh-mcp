//! The MCP server the daemon runs over each UDS connection.
//!
//! Two tools are offered. `list_hosts` shows the curated inventory — purpose
//! and policy only, never an address or credentials. `exec` runs a command.
//! Policy is not evaluated here: by the time a call reaches the daemon the
//! hook has already approved it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{Json, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

use crate::audit::AuditLog;
use crate::config::HostsConfig;
use crate::ssh::ConnectionPool;

/// A host as shown to the model: what it is for and how it is gated, never
/// its address or credentials.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct HostSummary {
    /// The logical name to pass to `exec`.
    pub alias: String,
    /// What the host is used for.
    pub purpose: String,
    /// Free-form tags for filtering.
    pub tags: Vec<String>,
    /// The policy gates guarding the host: `free`, `def`, `claude`, or `hook`.
    pub policy: Vec<String>,
}

/// The `list_hosts` result. The list is wrapped in an object because an MCP
/// tool's output schema must have an object at its root.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct HostList {
    pub hosts: Vec<HostSummary>,
}

/// Arguments to `exec`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ExecParams {
    /// The host alias, as returned by `list_hosts`.
    pub host: String,
    /// The shell command to run on the host.
    pub command: String,
}

/// The result of `exec`.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// One MCP session's view of the daemon. Cheap to clone — it shares the
/// daemon's connection pool and only adds a per-session tool router.
#[derive(Clone)]
pub struct SshMcpServer {
    pool: Arc<ConnectionPool>,
    config_path: PathBuf,
    audit: AuditLog,
    tool_router: ToolRouter<Self>,
}

#[tool_router(router = tool_router)]
impl SshMcpServer {
    /// Build a session that shares the daemon's connection pool and audit log.
    pub fn new(pool: Arc<ConnectionPool>, config_path: PathBuf, audit: AuditLog) -> Self {
        Self {
            pool,
            config_path,
            audit,
            tool_router: Self::tool_router(),
        }
    }

    /// Serve one MCP session over a connection until the client disconnects.
    pub async fn serve_connection(self, stream: UnixStream) -> Result<()> {
        let running = self
            .serve(stream)
            .await
            .context("the MCP session handshake failed")?;
        running
            .waiting()
            .await
            .context("the MCP session ended with an error")?;
        Ok(())
    }

    #[tool(
        name = "list_hosts",
        description = "List the SSH hosts available to run commands on. Each entry has an alias, its purpose, tags, and the policy gating it — never an address or credentials. Choose a host by purpose, then call exec with its alias."
    )]
    async fn list_hosts(&self) -> Result<Json<HostList>, String> {
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        let mut hosts: Vec<HostSummary> = config
            .hosts
            .iter()
            .map(|(alias, entry)| HostSummary {
                alias: alias.clone(),
                purpose: entry.purpose.clone(),
                tags: entry.tags.clone(),
                policy: entry
                    .policy
                    .iter()
                    .map(|gate| gate.kind().to_string())
                    .collect(),
            })
            .collect();
        hosts.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(Json(HostList { hosts }))
    }

    #[tool(
        name = "exec",
        description = "Run a shell command on a host from list_hosts and return its stdout, stderr, and exit code. Each call is stateless — no working directory or shell state carries to the next call, so use 'cd /path && cmd' when a directory matters."
    )]
    async fn exec(&self, params: Parameters<ExecParams>) -> Result<Json<ExecResult>, String> {
        let ExecParams { host, command } = params.0;
        let config = HostsConfig::load(&self.config_path).map_err(|e| format!("{e:#}"))?;
        let timeout = match config.host(&host) {
            Some(entry) => Duration::from_secs(config.exec_timeout_secs(entry)),
            None => return Err(format!("unknown host {host:?}")),
        };

        let result = self.pool.exec(&config, &host, &command, timeout).await;
        match &result {
            Ok(output) => self
                .audit
                .record(&host, &command, Some(output.exit_code), None),
            Err(error) => {
                let message = format!("{error:#}");
                self.audit.record(&host, &command, None, Some(&message));
            }
        }

        let output = result.map_err(|e| format!("{e:#}"))?;
        Ok(Json(ExecResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        }))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ssh-mcp", env!("CARGO_PKG_VERSION")))
    }
}
