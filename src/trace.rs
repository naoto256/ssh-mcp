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

/// A line-stream scope selector.
///
/// At least one of `grep`, `head`, or `tail` must be supplied — an entirely
/// empty op is rejected so the model cannot accidentally request an unscoped
/// dump. `head` and `tail` are mutually exclusive. When `grep` is combined
/// with `head` or `tail`, `grep` is applied first.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Op {
    /// Keep only lines matching this regex (Rust regex syntax).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grep: Option<String>,
    /// Keep the first N lines (applied after grep, if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<u32>,
    /// Keep the last N lines (applied after grep, if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail: Option<u32>,
}

impl Op {
    /// Reject an op that would imply "give me everything" and rule out
    /// combinations that have no obvious order.
    pub fn validate(&self) -> Result<(), String> {
        if self.grep.is_none() && self.head.is_none() && self.tail.is_none() {
            return Err(
                "op requires at least one of grep, head, or tail — output is otherwise unscoped"
                    .into(),
            );
        }
        if self.head.is_some() && self.tail.is_some() {
            return Err("op accepts head or tail, not both".into());
        }
        Ok(())
    }

    /// Apply the op to a list of plain text lines. Used by `exec`, where the
    /// stdout and stderr arrays are filtered independently and channel
    /// tagging is not in play.
    pub fn apply(&self, lines: Vec<String>) -> Result<(Vec<String>, u32), String> {
        let total = lines.len() as u32;
        let filtered: Vec<String> = if let Some(pattern) = &self.grep {
            let re = regex::Regex::new(pattern).map_err(|e| format!("invalid grep regex: {e}"))?;
            lines.into_iter().filter(|l| re.is_match(l)).collect()
        } else {
            lines
        };
        let scoped = if let Some(n) = self.head {
            filtered.into_iter().take(n as usize).collect()
        } else if let Some(n) = self.tail {
            let len = filtered.len();
            let skip = len.saturating_sub(n as usize);
            filtered.into_iter().skip(skip).collect()
        } else {
            filtered
        };
        Ok((scoped, total))
    }

    /// Apply the op to a list of channel-tagged lines, keeping the channel
    /// tag attached to each surviving line. `grep` matches against the bare
    /// text — never against any prefix — so a pattern that worked on the
    /// original `exec` output works here unchanged.
    pub fn apply_tagged(
        &self,
        lines: Vec<TraceLine>,
    ) -> Result<Vec<TraceLine>, String> {
        let filtered: Vec<TraceLine> = if let Some(pattern) = &self.grep {
            let re = regex::Regex::new(pattern).map_err(|e| format!("invalid grep regex: {e}"))?;
            lines.into_iter().filter(|l| re.is_match(&l.text)).collect()
        } else {
            lines
        };
        Ok(if let Some(n) = self.head {
            filtered.into_iter().take(n as usize).collect()
        } else if let Some(n) = self.tail {
            let len = filtered.len();
            let skip = len.saturating_sub(n as usize);
            filtered.into_iter().skip(skip).collect()
        } else {
            filtered
        })
    }
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
    fn validate_rejects_an_empty_op() {
        assert!(Op::default().validate().is_err());
    }

    #[test]
    fn validate_rejects_head_and_tail_together() {
        let op = Op {
            head: Some(10),
            tail: Some(10),
            ..Op::default()
        };
        assert!(op.validate().is_err());
    }

    #[test]
    fn apply_grep_then_tail_is_grep_first() {
        let op = Op {
            grep: Some("error".into()),
            tail: Some(2),
            ..Op::default()
        };
        let lines = vec![
            "error 1".into(),
            "info 2".into(),
            "error 3".into(),
            "info 4".into(),
            "error 5".into(),
        ];
        let (scoped, total) = op.apply(lines).unwrap();
        assert_eq!(total, 5);
        assert_eq!(scoped, vec!["error 3".to_string(), "error 5".to_string()]);
    }

    #[test]
    fn apply_tagged_filters_on_bare_text() {
        // The grep pattern matches the raw line content, not the channel
        // tag. A pattern that worked on the original exec output keeps
        // working through trace.
        let op = Op {
            grep: Some("^[1-9]$".into()),
            head: Some(3),
            ..Op::default()
        };
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
        let kept = op.apply_tagged(lines).unwrap();
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
