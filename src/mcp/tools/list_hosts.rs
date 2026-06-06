//! `list_hosts` body — turn the inventory into the model-facing summary
//! (alias, purpose, tags, policy kinds — never an address or credential).

use rmcp::Json;

use crate::config::HostsConfig;
use crate::mcp::HekateSshServer;
use crate::mcp::types::{HostList, HostSummary};

pub(in crate::mcp) async fn handle(server: &HekateSshServer) -> Result<Json<HostList>, String> {
    let config = HostsConfig::load(&server.config_path).map_err(|e| format!("{e:#}"))?;
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
