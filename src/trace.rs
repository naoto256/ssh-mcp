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

use std::collections::VecDeque;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// How many recent tool calls each session can re-inspect.
///
/// Five accommodates the bypass-permissions style where several calls fire in
/// quick succession before the user looks back — the trace for the third-back
/// call is still around.
pub const DEFAULT_TRACE_DEPTH: usize = 5;

/// Maximum bytes of body text retained per entry; longer bodies are
/// truncated and the entry is marked accordingly.
pub const TRACE_ENTRY_BYTE_CAP: usize = 10 * 1024 * 1024;

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

    /// Apply the op to a list of lines. Returns the scoped lines and the
    /// total line count *before* scoping, so the caller can show how much
    /// was filtered out.
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
    /// Body lines, channel-tagged for `exec`
    /// (`"stdout: ..."` / `"stderr: ..."`) and op-tagged for transfers
    /// (`"create path"` / `"update path"` / `"delete path"`).
    pub lines: Vec<String>,
    /// Optional companion list — for transfer entries this holds the
    /// hash-matched (skipped) paths, surfaced only when `include_skipped` is
    /// requested. Always empty for `exec`.
    pub skipped: Vec<String>,
    /// Set when either `lines` or `skipped` was truncated to fit the byte cap.
    pub truncated: bool,
}

/// Truncate a body to fit the entry byte cap. Lines beyond the cap are
/// dropped from the end; the caller flips `truncated` accordingly.
fn fit_to_cap(mut lines: Vec<String>) -> (Vec<String>, bool) {
    let mut total: usize = 0;
    let mut keep = 0usize;
    for (index, line) in lines.iter().enumerate() {
        // +1 accounts for the newline a caller would conceptually print.
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
///
/// Cheap to clone — the inner state is shared through an `Arc<Mutex<_>>` so
/// every tool handler on the same session writes into the same buffer.
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

    /// Append an entry, evicting the oldest if the buffer is full. The entry
    /// is truncated to fit the byte cap before it is stored.
    pub async fn record(&self, mut entry: TraceEntry) {
        let (capped_lines, lines_truncated) = fit_to_cap(entry.lines);
        let (capped_skipped, skipped_truncated) = fit_to_cap(entry.skipped);
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
        // Three lines match, then tail=2 keeps the last two of the matches —
        // not the last two of the original input.
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
    fn apply_head_takes_the_first_n() {
        let op = Op {
            head: Some(2),
            ..Op::default()
        };
        let lines = vec!["a".into(), "b".into(), "c".into()];
        let (scoped, total) = op.apply(lines).unwrap();
        assert_eq!(total, 3);
        assert_eq!(scoped, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn apply_tail_takes_the_last_n_even_when_fewer_lines_exist() {
        let op = Op {
            tail: Some(10),
            ..Op::default()
        };
        let lines = vec!["a".into(), "b".into()];
        let (scoped, total) = op.apply(lines).unwrap();
        assert_eq!(total, 2);
        assert_eq!(scoped, vec!["a".to_string(), "b".to_string()]);
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
        // 0 = newest, so the original first call is gone.
        assert_eq!(buf.fetch(0).await.unwrap().params, "call 2");
        assert_eq!(buf.fetch(1).await.unwrap().params, "call 1");
        assert!(buf.fetch(2).await.is_none());
    }

    #[tokio::test]
    async fn record_truncates_a_body_larger_than_the_cap() {
        // One line that on its own exceeds the cap; storage should mark
        // truncated and drop the line entirely.
        let big = "x".repeat(TRACE_ENTRY_BYTE_CAP + 100);
        let buf = TraceBuffer::new(1);
        buf.record(TraceEntry {
            tool: "exec".into(),
            params: String::new(),
            summary: String::new(),
            lines: vec!["ok".into(), big],
            skipped: vec![],
            truncated: false,
        })
        .await;
        let entry = buf.fetch(0).await.unwrap();
        assert!(entry.truncated);
        // The first line fit; the oversized one was dropped.
        assert_eq!(entry.lines, vec!["ok".to_string()]);
    }
}
