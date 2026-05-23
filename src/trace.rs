//! Per-session trace buffer for tool execution detail.
//!
//! Tool results are kept slim — counts and a small scoped excerpt — so the
//! model's context is not polluted by full output. The trace buffer keeps the
//! recent full detail in memory so the model can drill in deliberately by
//! calling the `trace` tool with an explicit scope (`tail`, `head`, or
//! `grep`).
//!
//! The buffer is per-session (per UDS connection); one session cannot see
//! another's traces.
//!
//! Lines are stored with a channel tag (`stdout` / `stderr` for `exec`,
//! `transfer` for `get` / `put` / `sync_*`) so the trace tool can filter by
//! stream and still apply `grep` against the bare text — the way the model
//! would write `grep` if it were inspecting the original tool result. The
//! tag also preserves the temporal interleaving the original chunks arrived
//! in, which is what makes a build-progress + warning log readable in
//! order.

use std::collections::VecDeque;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::ssh::OutputChannel;

/// How many recent tool calls each session can re-inspect.
pub const DEFAULT_TRACE_DEPTH: usize = 5;

/// Maximum bytes of body text retained per entry; longer bodies are
/// truncated and the entry is marked accordingly.
pub const TRACE_ENTRY_BYTE_CAP: usize = 10 * 1024 * 1024;

/// Which channel a single trace line belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// A line that came from an `exec` call's stdout.
    Stdout,
    /// A line that came from an `exec` call's stderr.
    Stderr,
    /// A line that describes a single change-set entry on a transfer call
    /// (e.g. `create src/foo.rs`). Transfers have no stdout/stderr concept;
    /// the stream selector is ignored for these lines.
    Transfer,
}

/// The stream selector accepted by `trace`. Decides which channels the body
/// is filtered to before `grep` is applied, and whether the output is
/// channel-prefixed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Stream {
    /// Only the stdout channel of an `exec` entry. Transfer lines pass
    /// through. Output has no prefix.
    Stdout,
    /// Only the stderr channel. Transfer lines pass through. No prefix.
    Stderr,
    /// Both `exec` channels in arrival order. Output is channel-prefixed
    /// (`stdout: ...` / `stderr: ...`) so the model can tell them apart.
    /// Transfer lines pass through unprefixed.
    #[default]
    Both,
}

impl Channel {
    /// Does this line pass the stream selector? Transfer lines always pass
    /// — the selector is a no-op for transfer entries.
    pub fn passes(self, stream: Stream) -> bool {
        match (self, stream) {
            (Channel::Transfer, _) => true,
            (Channel::Stdout, Stream::Stderr) => false,
            (Channel::Stderr, Stream::Stdout) => false,
            _ => true,
        }
    }
}

impl From<OutputChannel> for Channel {
    fn from(ch: OutputChannel) -> Self {
        match ch {
            OutputChannel::Stdout => Channel::Stdout,
            OutputChannel::Stderr => Channel::Stderr,
        }
    }
}

/// One line in a trace entry: text plus the channel it came from.
#[derive(Debug, Clone)]
pub struct TraceLine {
    pub channel: Channel,
    pub text: String,
}

/// One stage of an op pipeline. Exactly one of the four fields must be set
/// per step; combining them in a single step is rejected so the order of
/// operations in a step has no ambiguity. Multiple steps compose into a
/// pipeline by appearing in the order the caller wants them applied.
///
/// `full` is the implicit starting point — the body the step sees if it is
/// the first step — and is a no-op anywhere in the pipeline. It exists so
/// the caller can write `[{full: true}]` to mean "give me everything"
/// without having to add a dummy `head` or `tail`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct OpStep {
    /// Pass-through. Useful as the lone step when the caller wants the
    /// whole body. Has no effect mid-pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<bool>,
    /// Keep the first N lines of whatever the previous step produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<u32>,
    /// Keep the last N lines of whatever the previous step produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail: Option<u32>,
    /// Keep only lines matching this regex (Rust syntax) from whatever the
    /// previous step produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grep: Option<String>,
}

impl OpStep {
    /// Validate a single pipeline step: exactly one of `full=true`, `head`,
    /// `tail`, or `grep` must be set.
    pub fn validate(&self) -> Result<(), String> {
        let full_set = matches!(self.full, Some(true));
        let knobs = [
            full_set,
            self.head.is_some(),
            self.tail.is_some(),
            self.grep.is_some(),
        ];
        let set_count = knobs.iter().filter(|&&b| b).count();
        if set_count == 0 {
            return Err(
                "an op step needs exactly one of full=true, head, tail, or grep".into(),
            );
        }
        if set_count > 1 {
            return Err(
                "an op step accepts only one of full=true, head, tail, or grep — \
                 chain multiple steps to combine them"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Validate every step in a pipeline. An empty pipeline is allowed at this
/// level; the caller decides whether empty means "zero return" (exec) or
/// "missing required input" (trace).
pub fn validate_pipeline(steps: &[OpStep]) -> Result<(), String> {
    for (i, step) in steps.iter().enumerate() {
        step.validate()
            .map_err(|e| format!("op step {i}: {e}"))?;
    }
    Ok(())
}

/// Apply an op pipeline to a list of plain text lines, in order. `full` is a
/// pass-through; `head`/`tail`/`grep` narrow the running set. Returns the
/// final lines together with the pre-pipeline total so callers can report
/// how much was dropped.
pub fn apply_pipeline(
    lines: Vec<String>,
    steps: &[OpStep],
) -> Result<(Vec<String>, u32), String> {
    let total = lines.len() as u32;
    let mut cur = lines;
    for (i, step) in steps.iter().enumerate() {
        cur = apply_step_plain(cur, step).map_err(|e| format!("op step {i}: {e}"))?;
    }
    Ok((cur, total))
}

fn apply_step_plain(lines: Vec<String>, step: &OpStep) -> Result<Vec<String>, String> {
    if matches!(step.full, Some(true)) {
        return Ok(lines);
    }
    if let Some(n) = step.head {
        return Ok(lines.into_iter().take(n as usize).collect());
    }
    if let Some(n) = step.tail {
        let skip = lines.len().saturating_sub(n as usize);
        return Ok(lines.into_iter().skip(skip).collect());
    }
    if let Some(pattern) = &step.grep {
        let re = regex::Regex::new(pattern).map_err(|e| format!("invalid grep regex: {e}"))?;
        return Ok(lines.into_iter().filter(|l| re.is_match(l)).collect());
    }
    Err("step has no operation set".into())
}

/// Apply an op pipeline to channel-tagged lines, keeping the tags attached.
/// `grep` matches against the bare text — never against the channel prefix
/// — so a pattern that worked on the original `exec` result works here
/// unchanged.
pub fn apply_tagged_pipeline(
    lines: Vec<TraceLine>,
    steps: &[OpStep],
) -> Result<Vec<TraceLine>, String> {
    let mut cur = lines;
    for (i, step) in steps.iter().enumerate() {
        cur = apply_step_tagged(cur, step).map_err(|e| format!("op step {i}: {e}"))?;
    }
    Ok(cur)
}

fn apply_step_tagged(
    lines: Vec<TraceLine>,
    step: &OpStep,
) -> Result<Vec<TraceLine>, String> {
    if matches!(step.full, Some(true)) {
        return Ok(lines);
    }
    if let Some(n) = step.head {
        return Ok(lines.into_iter().take(n as usize).collect());
    }
    if let Some(n) = step.tail {
        let skip = lines.len().saturating_sub(n as usize);
        return Ok(lines.into_iter().skip(skip).collect());
    }
    if let Some(pattern) = &step.grep {
        let re = regex::Regex::new(pattern).map_err(|e| format!("invalid grep regex: {e}"))?;
        return Ok(lines.into_iter().filter(|l| re.is_match(&l.text)).collect());
    }
    Err("step has no operation set".into())
}

/// One trace entry: the full detail of a single tool call, recorded so the
/// model can re-inspect it later through the `trace` tool.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// The tool whose call produced this entry (e.g. `"exec"`).
    pub tool: String,
    /// Human-readable parameter summary for the originating call.
    pub params: String,
    /// Human-readable result summary (e.g. `"exit=0 stdout_lines=42"`).
    pub summary: String,
    /// Body lines in arrival order, each tagged with the channel they
    /// belong to. `exec` interleaves stdout and stderr here; transfers emit
    /// one line per change-set entry (all tagged `Transfer`).
    pub lines: Vec<TraceLine>,
    /// Optional companion list for transfer entries — the hash-matched
    /// (skipped) paths, surfaced only when `include_skipped` is requested.
    /// Always empty for `exec`.
    pub skipped: Vec<String>,
    /// Set when either `lines` or `skipped` was truncated to fit the byte
    /// cap.
    pub truncated: bool,
}

/// Truncate a tagged body to fit the entry byte cap. Lines beyond the cap
/// are dropped from the end; the caller flips `truncated` accordingly.
fn fit_lines_to_cap(mut lines: Vec<TraceLine>) -> (Vec<TraceLine>, bool) {
    let mut total: usize = 0;
    let mut keep = 0usize;
    for (index, line) in lines.iter().enumerate() {
        total = total.saturating_add(line.text.len().saturating_add(1));
        if total > TRACE_ENTRY_BYTE_CAP {
            keep = index;
            break;
        }
        keep = index + 1;
    }
    if keep < lines.len() {
        lines.truncate(keep);
        (lines, true)
    } else {
        (lines, false)
    }
}

/// Plain-string variant of the byte-cap fit, used for the `skipped`
/// companion list (transfer entries only).
fn fit_strings_to_cap(mut lines: Vec<String>) -> (Vec<String>, bool) {
    let mut total: usize = 0;
    let mut keep = 0usize;
    for (index, line) in lines.iter().enumerate() {
        total = total.saturating_add(line.len().saturating_add(1));
        if total > TRACE_ENTRY_BYTE_CAP {
            keep = index;
            break;
        }
        keep = index + 1;
    }
    if keep < lines.len() {
        lines.truncate(keep);
        (lines, true)
    } else {
        (lines, false)
    }
}

/// A per-session ring buffer of recent tool executions.
#[derive(Clone)]
pub struct TraceBuffer {
    inner: Arc<Mutex<VecDeque<TraceEntry>>>,
    depth: usize,
}

impl TraceBuffer {
    pub fn new(depth: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(depth))),
            depth,
        }
    }

    pub async fn record(&self, mut entry: TraceEntry) {
        let (capped_lines, lines_truncated) = fit_lines_to_cap(entry.lines);
        let (capped_skipped, skipped_truncated) = fit_strings_to_cap(entry.skipped);
        entry.lines = capped_lines;
        entry.skipped = capped_skipped;
        entry.truncated = lines_truncated || skipped_truncated;
        let mut buf = self.inner.lock().await;
        if buf.len() == self.depth {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// Fetch by zero-based index, where 0 is the most recent.
    pub async fn fetch(&self, index: usize) -> Option<TraceEntry> {
        let buf = self.inner.lock().await;
        let len = buf.len();
        if index >= len {
            return None;
        }
        buf.get(len - 1 - index).cloned()
    }
}

/// Split a sequence of `(channel, bytes)` chunks into ordered, channel-
/// tagged lines. Bytes that have not yet completed a line are held in a
/// per-channel buffer; whoever produces a `\n` first wins the next slot in
/// the output, so the natural reading order is preserved across stdout and
/// stderr. Any trailing partial lines are emitted at the end so no output
/// is silently dropped.
pub fn chunks_to_lines(chunks: &[(OutputChannel, Vec<u8>)]) -> Vec<TraceLine> {
    let mut out = Vec::new();
    let mut stdout_buf: Vec<u8> = Vec::new();
    let mut stderr_buf: Vec<u8> = Vec::new();
    for (ch, data) in chunks {
        let buf = match ch {
            OutputChannel::Stdout => &mut stdout_buf,
            OutputChannel::Stderr => &mut stderr_buf,
        };
        buf.extend_from_slice(data);
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = buf.drain(..=nl).collect();
            line.pop(); // strip the newline
            out.push(TraceLine {
                channel: (*ch).into(),
                text: String::from_utf8_lossy(&line).into_owned(),
            });
        }
    }
    if !stdout_buf.is_empty() {
        out.push(TraceLine {
            channel: Channel::Stdout,
            text: String::from_utf8_lossy(&stdout_buf).into_owned(),
        });
    }
    if !stderr_buf.is_empty() {
        out.push(TraceLine {
            channel: Channel::Stderr,
            text: String::from_utf8_lossy(&stderr_buf).into_owned(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_validate_rejects_empty_and_multi_knob_steps() {
        assert!(OpStep::default().validate().is_err());
        let multi = OpStep {
            head: Some(10),
            tail: Some(10),
            ..OpStep::default()
        };
        assert!(multi.validate().is_err());
        let full_and_grep = OpStep {
            full: Some(true),
            grep: Some("x".into()),
            ..OpStep::default()
        };
        assert!(full_and_grep.validate().is_err());
    }

    #[test]
    fn step_validate_accepts_each_single_knob() {
        assert!(OpStep {
            full: Some(true),
            ..OpStep::default()
        }
        .validate()
        .is_ok());
        assert!(OpStep {
            head: Some(5),
            ..OpStep::default()
        }
        .validate()
        .is_ok());
        assert!(OpStep {
            tail: Some(5),
            ..OpStep::default()
        }
        .validate()
        .is_ok());
        assert!(OpStep {
            grep: Some("x".into()),
            ..OpStep::default()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn pipeline_head_then_tail_is_a_sliding_window() {
        // [head 100, tail 50] on 200 lines = first 100, then last 50 of
        // those = lines 51..100. Composition order is the source of truth.
        let lines: Vec<String> = (1..=200).map(|i| i.to_string()).collect();
        let steps = vec![
            OpStep {
                head: Some(100),
                ..OpStep::default()
            },
            OpStep {
                tail: Some(50),
                ..OpStep::default()
            },
        ];
        let (scoped, total) = apply_pipeline(lines, &steps).unwrap();
        assert_eq!(total, 200);
        assert_eq!(scoped.len(), 50);
        assert_eq!(scoped.first().map(String::as_str), Some("51"));
        assert_eq!(scoped.last().map(String::as_str), Some("100"));
    }

    #[test]
    fn pipeline_full_is_a_passthrough() {
        let lines = vec!["a".into(), "b".into(), "c".into()];
        let steps = vec![OpStep {
            full: Some(true),
            ..OpStep::default()
        }];
        let (scoped, _total) = apply_pipeline(lines.clone(), &steps).unwrap();
        assert_eq!(scoped, lines);

        // Mid-pipeline `full` is also a no-op; the surrounding steps still
        // narrow.
        let steps_mid = vec![
            OpStep {
                head: Some(2),
                ..OpStep::default()
            },
            OpStep {
                full: Some(true),
                ..OpStep::default()
            },
        ];
        let (scoped_mid, _total) = apply_pipeline(lines, &steps_mid).unwrap();
        assert_eq!(scoped_mid, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn pipeline_order_matters_for_grep_combinations() {
        // `[grep error, tail 2]` keeps the last 2 of the matching lines.
        let lines = vec![
            "error 1".into(),
            "info".into(),
            "error 3".into(),
            "error 5".into(),
        ];
        let steps = vec![
            OpStep {
                grep: Some("error".into()),
                ..OpStep::default()
            },
            OpStep {
                tail: Some(2),
                ..OpStep::default()
            },
        ];
        let (scoped, _total) = apply_pipeline(lines.clone(), &steps).unwrap();
        assert_eq!(scoped, vec!["error 3".to_string(), "error 5".to_string()]);

        // Reverse: `[tail 2, grep error]` first takes the last 2 lines
        // (one of which doesn't match), then greps — a smaller result.
        let lines = vec![
            "error 1".into(),
            "info".into(),
            "error 3".into(),
            "trailing info".into(),
        ];
        let steps_rev = vec![
            OpStep {
                tail: Some(2),
                ..OpStep::default()
            },
            OpStep {
                grep: Some("error".into()),
                ..OpStep::default()
            },
        ];
        let (scoped_rev, _total) = apply_pipeline(lines, &steps_rev).unwrap();
        assert_eq!(scoped_rev, vec!["error 3".to_string()]);
    }

    #[test]
    fn apply_tagged_pipeline_filters_on_bare_text() {
        // The grep pattern matches the raw line content, not the channel
        // tag. A pattern that worked on the original exec output keeps
        // working through trace.
        let steps = vec![
            OpStep {
                grep: Some("^[1-9]$".into()),
                ..OpStep::default()
            },
            OpStep {
                head: Some(3),
                ..OpStep::default()
            },
        ];
        let lines = vec![
            TraceLine {
                channel: Channel::Stdout,
                text: "1".into(),
            },
            TraceLine {
                channel: Channel::Stderr,
                text: "warn".into(),
            },
            TraceLine {
                channel: Channel::Stdout,
                text: "2".into(),
            },
            TraceLine {
                channel: Channel::Stdout,
                text: "3".into(),
            },
            TraceLine {
                channel: Channel::Stdout,
                text: "10".into(), // does not match [1-9] alone
            },
        ];
        let kept = apply_tagged_pipeline(lines, &steps).unwrap();
        assert_eq!(kept.len(), 3);
        assert_eq!(kept[0].text, "1");
        assert_eq!(kept[1].text, "2");
        assert_eq!(kept[2].text, "3");
    }

    #[tokio::test]
    async fn buffer_evicts_oldest_when_full() {
        let buf = TraceBuffer::new(2);
        for i in 0..3 {
            buf.record(TraceEntry {
                tool: "exec".into(),
                params: format!("call {i}"),
                summary: String::new(),
                lines: vec![],
                skipped: vec![],
                truncated: false,
            })
            .await;
        }
        assert_eq!(buf.fetch(0).await.unwrap().params, "call 2");
        assert_eq!(buf.fetch(1).await.unwrap().params, "call 1");
        assert!(buf.fetch(2).await.is_none());
    }

    #[tokio::test]
    async fn record_truncates_a_body_larger_than_the_cap() {
        let big = "x".repeat(TRACE_ENTRY_BYTE_CAP + 100);
        let buf = TraceBuffer::new(1);
        buf.record(TraceEntry {
            tool: "exec".into(),
            params: String::new(),
            summary: String::new(),
            lines: vec![
                TraceLine {
                    channel: Channel::Stdout,
                    text: "ok".into(),
                },
                TraceLine {
                    channel: Channel::Stdout,
                    text: big,
                },
            ],
            skipped: vec![],
            truncated: false,
        })
        .await;
        let entry = buf.fetch(0).await.unwrap();
        assert!(entry.truncated);
        assert_eq!(entry.lines.len(), 1);
        assert_eq!(entry.lines[0].text, "ok");
    }

    #[test]
    fn chunks_to_lines_preserves_interleaving() {
        // stdout writes "progress", then stderr emits a complete "warn"
        // line, then stdout completes its first line — the reader expects
        // the stderr line to appear first (it completed first), and the
        // stdout line to follow.
        let chunks = vec![
            (OutputChannel::Stdout, b"progress".to_vec()),
            (OutputChannel::Stderr, b"warn\n".to_vec()),
            (OutputChannel::Stdout, b" 1\n".to_vec()),
            (OutputChannel::Stdout, b"progress 2\n".to_vec()),
        ];
        let lines = chunks_to_lines(&chunks);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].channel, Channel::Stderr);
        assert_eq!(lines[0].text, "warn");
        assert_eq!(lines[1].channel, Channel::Stdout);
        assert_eq!(lines[1].text, "progress 1");
        assert_eq!(lines[2].channel, Channel::Stdout);
        assert_eq!(lines[2].text, "progress 2");
    }

    #[test]
    fn chunks_to_lines_flushes_trailing_partial_lines() {
        // No final newline — but the bytes must still surface or output
        // would be silently dropped.
        let chunks = vec![
            (OutputChannel::Stdout, b"done\n".to_vec()),
            (OutputChannel::Stdout, b"oops no newline".to_vec()),
        ];
        let lines = chunks_to_lines(&chunks);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].text, "oops no newline");
    }

    #[test]
    fn channel_passes_stream_correctly() {
        assert!(Channel::Stdout.passes(Stream::Both));
        assert!(Channel::Stdout.passes(Stream::Stdout));
        assert!(!Channel::Stdout.passes(Stream::Stderr));
        assert!(Channel::Stderr.passes(Stream::Stderr));
        assert!(!Channel::Stderr.passes(Stream::Stdout));
        // Transfer is the no-op case: every stream selector lets it through.
        assert!(Channel::Transfer.passes(Stream::Stdout));
        assert!(Channel::Transfer.passes(Stream::Stderr));
        assert!(Channel::Transfer.passes(Stream::Both));
    }
}
