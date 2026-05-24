//! `exec` body and its only co-resident helper, `detect_trailing_scope_pipe`
//! (the heuristic that surfaces the "you piped through `tail` again"
//! advisory on the result).

use std::time::Duration;

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;

use crate::config::HostsConfig;
use crate::mcp::SshMcpServer;
use crate::mcp::types::{ExecParams, ExecResult};
use crate::trace::{TraceEntry, apply_pipeline, chunks_to_lines, validate_pipeline};

pub(in crate::mcp) async fn handle(
    server: &SshMcpServer,
    params: Parameters<ExecParams>,
) -> Result<Json<ExecResult>, String> {
    let ExecParams { host, command, op } = params.0;
    validate_pipeline(&op)?;
    let config = HostsConfig::load(&server.config_path).map_err(|e| format!("{e:#}"))?;
    let timeout = match config.host(&host) {
        Some(entry) => Duration::from_secs(config.exec_timeout_secs(entry)),
        None => return Err(format!("unknown host {host:?}")),
    };

    // The remote runs the command verbatim. The pool reads its
    // pooled connection's encoding (probed once at connect time)
    // and decodes the returned bytes accordingly, so the daemon
    // hands back UTF-8 strings regardless of whether the host is a
    // UTF-8 POSIX box or a CP932 Japanese Windows host.
    let result = server.pool.exec(&config, &host, &command, timeout).await;
    match &result {
        Ok(output) => server
            .audit
            .record_exec(&host, &command, Some(output.exit_code), None),
        Err(error) => {
            let message = format!("{error:#}");
            server
                .audit
                .record_exec(&host, &command, None, Some(&message));
        }
    }

    let output = result.map_err(|e| format!("{e:#}"))?;
    let stdout_all: Vec<String> = output.stdout.lines().map(String::from).collect();
    let stderr_all: Vec<String> = output.stderr.lines().map(String::from).collect();

    // The trace buffer holds the channel-tagged body in arrival order:
    // splitting the raw chunks gives the natural reading order of
    // progress lines and the warnings that landed between them, which
    // is what makes a long build log readable through `trace`.
    let trace_lines = chunks_to_lines(&output.chunks);
    let trace_summary = format!(
        "exit={} stdout_lines={} stderr_lines={}",
        output.exit_code,
        stdout_all.len(),
        stderr_all.len()
    );
    server
        .trace
        .record(TraceEntry {
            tool: "exec".into(),
            params: format!("host={host:?} command={command:?}"),
            summary: trace_summary,
            lines: trace_lines,
            skipped: vec![],
            truncated: false,
        })
        .await;

    let (stdout, stdout_lines) = if op.is_empty() {
        // Body is omitted from the result; counts still come back so
        // the model can decide whether to drill into trace.
        (Vec::new(), stdout_all.len() as u32)
    } else {
        apply_pipeline(stdout_all, &op)?
    };
    let (stderr, stderr_lines) = if op.is_empty() {
        (Vec::new(), stderr_all.len() as u32)
    } else {
        apply_pipeline(stderr_all, &op)?
    };
    let note = detect_trailing_scope_pipe(&command).map(|program| {
        format!(
            "the command ends in `| {program}` — the shell scoped the output before the \
             daemon saw it, so the trace buffer only holds what survived the pipe. Pass \
             `op` (tail/head/grep) instead and let `trace` re-scope from the full stream."
        )
    });
    Ok(Json(ExecResult {
        exit_code: output.exit_code,
        stdout,
        stdout_lines,
        stderr,
        stderr_lines,
        note,
    }))
}

/// If the command's last unquoted pipe targets a line-scoping program,
/// return that program's name. The intent is to recognise the
/// "double-scoping" anti-pattern — piping through `tail` / `head` / `grep`
/// when the `op` parameter exists for exactly that purpose — and surface
/// an advisory `note` to the caller. Best-effort: a naive quote-aware scan
/// is enough to catch the common cases without growing a shell parser.
fn detect_trailing_scope_pipe(command: &str) -> Option<&'static str> {
    let bytes = command.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut last_pipe: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'\\' if !in_single && i + 1 < bytes.len() => {
                // Skip the escaped byte. (Inside single quotes `\` is
                // literal, so we only honour escapes outside single
                // quoting.)
                i += 2;
                continue;
            }
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'|' if !in_single && !in_double => {
                // `||` is logical-or, not a pipe — skip both bytes.
                if bytes.get(i + 1) == Some(&b'|') {
                    i += 2;
                    continue;
                }
                last_pipe = Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    let idx = last_pipe?;
    let after = &command[idx + 1..].trim_start();
    let first_word = after
        .split(|c: char| c.is_whitespace())
        .find(|w| !w.is_empty())?;
    match first_word {
        "tail" => Some("tail"),
        "head" => Some("head"),
        "grep" => Some("grep"),
        "egrep" => Some("egrep"),
        "fgrep" => Some("fgrep"),
        "rg" => Some("rg"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_trailing_tail_pipe() {
        assert_eq!(detect_trailing_scope_pipe("ls -la | tail -5"), Some("tail"));
    }

    #[test]
    fn detects_a_trailing_grep_after_an_unrelated_pipe() {
        // The model used awk to extract, then grep to scope — the *last*
        // pipe is the one that mattered for the advisory.
        assert_eq!(
            detect_trailing_scope_pipe("ls | awk '{print $1}' | grep foo"),
            Some("grep")
        );
    }

    #[test]
    fn ignores_a_pipe_inside_quotes() {
        // The `|` lives inside single quotes — not a real pipe operator.
        assert!(detect_trailing_scope_pipe("echo 'a | tail'").is_none());
        assert!(detect_trailing_scope_pipe(r#"echo "a | grep b""#).is_none());
    }

    #[test]
    fn ignores_logical_or() {
        // `||` is logical-or, not a pipe.
        assert!(detect_trailing_scope_pipe("cmd1 || cmd2").is_none());
    }

    #[test]
    fn ignores_unrelated_trailing_pipe_targets() {
        // `wc` and `sort` aren't on the scoping list; the model using them
        // is doing something different, not double-scoping.
        assert!(detect_trailing_scope_pipe("ls | wc -l").is_none());
        assert!(detect_trailing_scope_pipe("ls | sort").is_none());
    }

    #[test]
    fn detects_through_a_redirect_block_correctly() {
        // The `2>&1` is not a pipe; the last real pipe still targets head.
        assert_eq!(
            detect_trailing_scope_pipe("cmd 2>&1 | head -3"),
            Some("head")
        );
    }

    #[test]
    fn returns_none_when_there_is_no_pipe() {
        assert!(detect_trailing_scope_pipe("ls -la").is_none());
        assert!(detect_trailing_scope_pipe("echo hi; echo bye").is_none());
    }
}
