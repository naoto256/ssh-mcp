//! `list_agent_keys` body — surface the public identities the user's SSH
//! agent currently holds (`ssh-add -L` equivalent).
//!
//! The model never sees private key material — the agent socket is the only
//! thing that can sign, and we only read public bytes. The tool exists so
//! The agent can tell the user *which* `authorized_keys` line to paste onto a
//! freshly proposed host, and to diagnose "agent has no key" failures.
//!
//! Certificate identities (`AgentIdentity::Certificate`) are skipped — they
//! are not what users typically paste into `authorized_keys` and would
//! complicate the output shape. Plain public keys cover the common case.

use rmcp::Json;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::HashAlg;

use crate::mcp::HekateSshServer;
use crate::mcp::types::{AgentKey, AgentKeyList};

pub(in crate::mcp) async fn handle(
    _server: &HekateSshServer,
) -> Result<Json<AgentKeyList>, String> {
    let mut agent = AgentClient::connect_env()
        .await
        .map_err(|e| format!("could not reach the SSH agent ($SSH_AUTH_SOCK): {e}"))?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| format!("could not list SSH agent identities: {e}"))?;

    let mut keys = Vec::with_capacity(identities.len());
    for identity in identities {
        let (key, comment) = match identity {
            AgentIdentity::PublicKey { key, comment } => (key, comment),
            // Certificates are intentionally skipped — see the module
            // docstring.
            AgentIdentity::Certificate { .. } => continue,
        };
        let public_key = key
            .to_openssh()
            .map_err(|e| format!("could not serialize an agent key to OpenSSH: {e}"))?;
        keys.push(AgentKey {
            r#type: key.algorithm().as_str().to_string(),
            comment,
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            public_key,
        });
    }

    Ok(Json(AgentKeyList { keys }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;

    /// The output schema must be an object whose `keys` property is an
    /// array. rmcp requires object roots, and the caller depends on the
    /// exact field names.
    #[test]
    fn agent_key_list_schema_shape() {
        let schema = schema_for!(AgentKeyList);
        let json = serde_json::to_value(&schema).unwrap();
        assert_eq!(json["type"], "object");
        assert!(json["properties"]["keys"].is_object());
        assert_eq!(json["properties"]["keys"]["type"], "array");
    }

    /// Each entry must carry the four fields the tool description advertises.
    #[test]
    fn agent_key_schema_shape() {
        let schema = schema_for!(AgentKey);
        let json = serde_json::to_value(&schema).unwrap();
        let props = &json["properties"];
        for field in ["type", "comment", "fingerprint", "public_key"] {
            assert!(
                props[field].is_object(),
                "missing property {field} in AgentKey schema",
            );
        }
    }

    /// An empty list must round-trip through serde as `{"keys": []}`, not
    /// `null` or a missing field — the model's prompt expects the field
    /// always to be present.
    #[test]
    fn empty_list_serializes_with_empty_array() {
        let list = AgentKeyList { keys: vec![] };
        let s = serde_json::to_string(&list).unwrap();
        assert_eq!(s, r#"{"keys":[]}"#);
    }
}
