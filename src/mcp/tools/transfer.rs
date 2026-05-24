//! The four file-transfer tool bodies (`get` / `put` / `sync_get` /
//! `sync_put`) plus their one shared helper for recording the per-file
//! detail of a sync into the trace ring buffer.

use std::time::Duration;

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;

use crate::changeset::ChangeOp;
use crate::config::HostsConfig;
use crate::mcp::SshMcpServer;
use crate::mcp::types::{
    GetParams, PutParams, SyncGetParams, SyncPutParams, SyncResult, TransferResult,
};
use crate::pathnorm;
use crate::trace::{Channel, TraceEntry, TraceLine};

pub(in crate::mcp) async fn handle_get(
    server: &SshMcpServer,
    params: Parameters<GetParams>,
) -> Result<Json<TransferResult>, String> {
    let GetParams {
        host,
        remote_path,
        local_path,
        exclude,
    } = params.0;
    let config = HostsConfig::load(&server.config_path).map_err(|e| format!("{e:#}"))?;
    // The download exclude is per-host (the remote tree is host-specific);
    // the tool argument adds more for this call.
    let (timeout, mut excludes) = match config.host(&host) {
        Some(entry) => (
            Duration::from_secs(config.exec_timeout_secs(entry)),
            entry.exclude.clone(),
        ),
        None => return Err(format!("unknown host {host:?}")),
    };
    excludes.extend(exclude);
    // Normalize exactly as the policy gate did, so the two cannot disagree.
    let remote = pathnorm::normalize_remote(&remote_path).map_err(|e| format!("{e:#}"))?;
    let local = pathnorm::normalize_local(&local_path).map_err(|e| format!("{e:#}"))?;

    let result = server
        .pool
        .get_file(&config, &host, &remote, &local, &excludes, timeout)
        .await;
    let local_display = local.to_string_lossy();
    match &result {
        Ok(stats) => server.audit.record_transfer(
            "get",
            &host,
            &remote,
            &local_display,
            Some(stats.bytes),
            None,
        ),
        Err(error) => {
            let message = format!("{error:#}");
            server.audit.record_transfer(
                "get",
                &host,
                &remote,
                &local_display,
                None,
                Some(&message),
            );
        }
    }

    let stats = result.map_err(|e| format!("{e:#}"))?;
    Ok(Json(TransferResult { bytes: stats.bytes }))
}

pub(in crate::mcp) async fn handle_put(
    server: &SshMcpServer,
    params: Parameters<PutParams>,
) -> Result<Json<TransferResult>, String> {
    let PutParams {
        host,
        local_path,
        remote_path,
        exclude,
    } = params.0;
    let config = HostsConfig::load(&server.config_path).map_err(|e| format!("{e:#}"))?;
    let timeout = match config.host(&host) {
        Some(entry) => Duration::from_secs(config.exec_timeout_secs(entry)),
        None => return Err(format!("unknown host {host:?}")),
    };
    let remote = pathnorm::normalize_remote(&remote_path).map_err(|e| format!("{e:#}"))?;
    let local = pathnorm::normalize_local(&local_path).map_err(|e| format!("{e:#}"))?;

    // The upload exclude is global (the source tree's property, not the
    // host's); the tool argument adds more for this call.
    let mut excludes = config.defaults.exclude.clone();
    excludes.extend(exclude);

    let result = server
        .pool
        .put_file(&config, &host, &local, &remote, &excludes, timeout)
        .await;
    let local_display = local.to_string_lossy();
    match &result {
        Ok(stats) => server.audit.record_transfer(
            "put",
            &host,
            &remote,
            &local_display,
            Some(stats.bytes),
            None,
        ),
        Err(error) => {
            let message = format!("{error:#}");
            server.audit.record_transfer(
                "put",
                &host,
                &remote,
                &local_display,
                None,
                Some(&message),
            );
        }
    }

    let stats = result.map_err(|e| format!("{e:#}"))?;
    Ok(Json(TransferResult { bytes: stats.bytes }))
}

pub(in crate::mcp) async fn handle_sync_get(
    server: &SshMcpServer,
    params: Parameters<SyncGetParams>,
) -> Result<Json<SyncResult>, String> {
    let SyncGetParams {
        host,
        remote_path,
        local_path,
        exclude,
    } = params.0;
    let config = HostsConfig::load(&server.config_path).map_err(|e| format!("{e:#}"))?;
    let (timeout, mut excludes) = match config.host(&host) {
        Some(entry) => (
            Duration::from_secs(config.exec_timeout_secs(entry)),
            entry.exclude.clone(),
        ),
        None => return Err(format!("unknown host {host:?}")),
    };
    excludes.extend(exclude);
    let remote = pathnorm::normalize_remote(&remote_path).map_err(|e| format!("{e:#}"))?;
    let local = pathnorm::normalize_local(&local_path).map_err(|e| format!("{e:#}"))?;

    let result = server
        .pool
        .sync_get(&config, &host, &remote, &local, &excludes, timeout)
        .await;
    let local_display = local.to_string_lossy();
    match &result {
        Ok(sr) => server.audit.record_transfer(
            "sync_get",
            &host,
            &remote,
            &local_display,
            Some(sr.bytes),
            None,
        ),
        Err(error) => {
            let message = format!("{error:#}");
            server.audit.record_transfer(
                "sync_get",
                &host,
                &remote,
                &local_display,
                None,
                Some(&message),
            );
        }
    }
    let sr = result.map_err(|e| format!("{e:#}"))?;
    let counts = sr.change_set.counts();
    record_transfer_trace(server, "sync_get", &host, &remote, &local_display, &sr).await;
    Ok(Json(SyncResult {
        bytes: sr.bytes,
        created: counts.created,
        updated: counts.updated,
        deleted: counts.deleted,
        skipped: counts.skipped,
    }))
}

pub(in crate::mcp) async fn handle_sync_put(
    server: &SshMcpServer,
    params: Parameters<SyncPutParams>,
) -> Result<Json<SyncResult>, String> {
    let SyncPutParams {
        host,
        local_path,
        remote_path,
        exclude,
    } = params.0;
    let config = HostsConfig::load(&server.config_path).map_err(|e| format!("{e:#}"))?;
    let timeout = match config.host(&host) {
        Some(entry) => Duration::from_secs(config.exec_timeout_secs(entry)),
        None => return Err(format!("unknown host {host:?}")),
    };
    let remote = pathnorm::normalize_remote(&remote_path).map_err(|e| format!("{e:#}"))?;
    let local = pathnorm::normalize_local(&local_path).map_err(|e| format!("{e:#}"))?;

    let mut excludes = config.defaults.exclude.clone();
    excludes.extend(exclude);

    let result = server
        .pool
        .sync_put(&config, &host, &local, &remote, &excludes, timeout)
        .await;
    let local_display = local.to_string_lossy();
    match &result {
        Ok(sr) => server.audit.record_transfer(
            "sync_put",
            &host,
            &remote,
            &local_display,
            Some(sr.bytes),
            None,
        ),
        Err(error) => {
            let message = format!("{error:#}");
            server.audit.record_transfer(
                "sync_put",
                &host,
                &remote,
                &local_display,
                None,
                Some(&message),
            );
        }
    }
    let sr = result.map_err(|e| format!("{e:#}"))?;
    let counts = sr.change_set.counts();
    record_transfer_trace(server, "sync_put", &host, &remote, &local_display, &sr).await;
    Ok(Json(SyncResult {
        bytes: sr.bytes,
        created: counts.created,
        updated: counts.updated,
        deleted: counts.deleted,
        skipped: counts.skipped,
    }))
}

/// Build the line-oriented trace body for a transfer (`<op> <rel_path>`
/// per line; the skipped paths are stashed separately so the model can
/// opt in to them through `include_skipped`).
async fn record_transfer_trace(
    server: &SshMcpServer,
    tool: &str,
    host: &str,
    remote: &str,
    local: &str,
    sr: &crate::ssh::SyncResult,
) {
    // Transfer lines have no stdout/stderr distinction; tag them as
    // Transfer so the stream selector in `trace` passes them through
    // unchanged regardless of which channel the caller asked for.
    let mut lines = Vec::new();
    let mut skipped = Vec::new();
    for entry in &sr.change_set.entries {
        let text = format!("{} {}", entry.op.verb(), entry.rel_path.display());
        if entry.op == ChangeOp::Skip {
            skipped.push(text);
        } else {
            lines.push(TraceLine {
                channel: Channel::Transfer,
                text,
            });
        }
    }
    let counts = sr.change_set.counts();
    let summary = format!(
        "bytes={} created={} updated={} deleted={} skipped={}",
        sr.bytes, counts.created, counts.updated, counts.deleted, counts.skipped
    );
    server
        .trace
        .record(TraceEntry {
            tool: tool.into(),
            params: format!("host={host:?} remote={remote:?} local={local:?}"),
            summary,
            lines,
            skipped,
            truncated: false,
        })
        .await;
}
