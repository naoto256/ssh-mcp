//! `trace` body — re-inspect a recent tool call from the per-session
//! ring buffer with the same op pipeline shape that `exec` uses.

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;

use crate::mcp::HekateSshServer;
use crate::mcp::types::{TraceParams, TraceResult};
use crate::trace::{Channel, Stream, TraceLine, apply_tagged_pipeline, validate_pipeline};

pub(in crate::mcp) async fn handle(
    server: &HekateSshServer,
    params: Parameters<TraceParams>,
) -> Result<Json<TraceResult>, String> {
    let TraceParams {
        index,
        op,
        stream,
        include_skipped,
    } = params.0;
    if op.is_empty() {
        return Err(
            "trace requires at least one op step — pass `[{full: true}]` for the whole body, \
             or chain head/tail/grep to narrow"
                .into(),
        );
    }
    validate_pipeline(&op)?;
    let entry = server
        .trace
        .fetch(index as usize)
        .await
        .ok_or_else(|| format!("no trace entry at index {index}"))?;

    // Raw per-channel counts of the recorded entry (before any filter).
    // These match the exec result's stdout_lines / stderr_lines so the
    // model has the same anchor whether it is reading the original
    // result or the trace.
    let stdout_lines_raw = entry
        .lines
        .iter()
        .filter(|l| l.channel == Channel::Stdout)
        .count() as u32;
    let stderr_lines_raw = entry
        .lines
        .iter()
        .filter(|l| l.channel == Channel::Stderr)
        .count() as u32;

    // Stream filter: keep lines whose channel matches the selector.
    // Transfer lines always pass through.
    let mut body: Vec<TraceLine> = entry
        .lines
        .iter()
        .filter(|l| l.channel.passes(stream))
        .cloned()
        .collect();
    // Skipped paths are channel-less; treat them as Transfer for output
    // formatting purposes (no prefix).
    if include_skipped {
        body.extend(entry.skipped.iter().map(|s| TraceLine {
            channel: Channel::Transfer,
            text: s.clone(),
        }));
    }
    // `total_lines` is meaningful for transfer entries — they have no
    // stdout/stderr split, so it's the only count the caller can read.
    // For `exec`, it would be a pure derivation of stdout_lines /
    // stderr_lines and the stream selector, so it is omitted.
    let is_transfer = body.iter().any(|l| l.channel == Channel::Transfer)
        || (stdout_lines_raw == 0 && stderr_lines_raw == 0);
    let total_lines = if is_transfer {
        Some(body.len() as u32)
    } else {
        None
    };

    let kept = apply_tagged_pipeline(body, &op)?;
    // Output formatting: prefix exec channels only when `stream = both`
    // (otherwise the prefix is unambiguous from the parameter the
    // caller already chose).
    let lines: Vec<String> = kept
        .into_iter()
        .map(|line| match (line.channel, stream) {
            (Channel::Stdout, Stream::Both) => format!("stdout: {}", line.text),
            (Channel::Stderr, Stream::Both) => format!("stderr: {}", line.text),
            _ => line.text,
        })
        .collect();

    Ok(Json(TraceResult {
        tool: entry.tool,
        params: entry.params,
        summary: entry.summary,
        lines,
        stdout_lines: stdout_lines_raw,
        stderr_lines: stderr_lines_raw,
        total_lines,
        truncated: entry.truncated,
    }))
}
