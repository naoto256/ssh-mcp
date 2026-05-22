//! Shell-command analysis for the evaluator: splitting compound commands,
//! stripping process wrappers, and recognizing file commands.
//!
//! This mirrors how Claude Code itself decomposes a Bash command before
//! matching it against permission rules. It is deliberately conservative:
//! when the analysis is unsure it leaves more of the command intact, which
//! makes an allow rule match less (never more).

/// One token of a command line, with its byte offset in the source string.
struct Token {
    start: usize,
    /// The token with surrounding quotes removed.
    text: String,
}

/// Tokenize a command line, tracking the byte offset where each token begins.
///
/// Quote handling is pragmatic: single and double quotes group tokens and are
/// stripped from the result; a backslash escapes the next character. This does
/// not interpret `$(...)`, parameter expansion, or here-docs.
fn tokenize(s: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut text = String::new();
    let mut start = 0;
    let mut started = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = s.char_indices().peekable();

    while let Some((idx, c)) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                if !started {
                    started = true;
                    start = idx;
                }
            }
            '"' if !in_single => {
                in_double = !in_double;
                if !started {
                    started = true;
                    start = idx;
                }
            }
            '\\' if !in_single => {
                if let Some((_, next)) = chars.next() {
                    if !started {
                        started = true;
                        start = idx;
                    }
                    text.push(next);
                }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if started {
                    tokens.push(Token {
                        start,
                        text: std::mem::take(&mut text),
                    });
                    started = false;
                }
            }
            c => {
                if !started {
                    started = true;
                    start = idx;
                }
                text.push(c);
            }
        }
    }
    if started {
        tokens.push(Token { start, text });
    }
    tokens
}

/// Split a command on shell operators into independently-evaluated
/// subcommands. Recognized separators are `;`, newline, and any run of `&`
/// and `|` (covering `&&`, `||`, `|&`, `|`, and `&`). Separators inside
/// quotes are ignored.
pub fn split_compound(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = command.chars().peekable();

    let flush = |parts: &mut Vec<String>, current: &mut String| {
        let trimmed = current.trim();
        if !trimmed.is_empty() {
            parts.push(trimmed.to_string());
        }
        current.clear();
    };

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(c);
            }
            '\\' if !in_single && !in_double => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            _ if in_single || in_double => current.push(c),
            ';' | '\n' => flush(&mut parts, &mut current),
            '&' | '|' => {
                flush(&mut parts, &mut current);
                while matches!(chars.peek(), Some('&') | Some('|')) {
                    chars.next();
                }
            }
            _ => current.push(c),
        }
    }
    flush(&mut parts, &mut current);
    parts
}

/// Process wrappers whose only argument is the wrapped command, optionally
/// preceded by flags.
const PLAIN_WRAPPERS: &[&str] = &["nohup", "time"];

/// The bare command name of `path`, stripping any leading directory.
fn base_name(arg: &str) -> &str {
    arg.rsplit('/').next().unwrap_or(arg)
}

/// Count the leading flag tokens, consuming the value of any flag listed in
/// `value_flags` that is written as a separate token.
fn count_flags(tokens: &[Token], value_flags: &[&str]) -> usize {
    let mut i = 0;
    while i < tokens.len() && tokens[i].text.starts_with('-') {
        let takes_value = value_flags.contains(&tokens[i].text.as_str());
        i += 1;
        if takes_value && i < tokens.len() {
            i += 1;
        }
    }
    i
}

/// The number of leading tokens that form a process wrapper plus its
/// arguments, or 0 when `tokens[0]` is not a recognized wrapper.
fn wrapper_len(tokens: &[Token]) -> usize {
    if tokens.is_empty() {
        return 0;
    }
    match base_name(&tokens[0].text) {
        name if PLAIN_WRAPPERS.contains(&name) => 1 + count_flags(&tokens[1..], &[]),
        "nice" => 1 + count_flags(&tokens[1..], &["-n", "--adjustment"]),
        "stdbuf" => 1 + count_flags(&tokens[1..], &["-i", "-o", "-e"]),
        "timeout" => {
            let mut i = 1 + count_flags(&tokens[1..], &["-s", "--signal", "-k", "--kill-after"]);
            // Skip the duration positional.
            if i < tokens.len() && !tokens[i].text.starts_with('-') {
                i += 1;
            }
            i
        }
        // Bare `xargs` is stripped; `xargs` with flags is treated as its own
        // command, since the flags change which inner command actually runs.
        "xargs" if tokens.len() > 1 && !tokens[1].text.starts_with('-') => 1,
        _ => 0,
    }
}

/// A command with its process wrappers removed.
pub struct Stripped<'a> {
    /// The effective command string, suitable for matching against Bash rules.
    pub command: &'a str,
    /// The effective command's tokens, with quotes removed.
    pub argv: Vec<String>,
}

/// Strip process wrappers (`timeout`, `nice`, `nohup`, ...) from a subcommand.
///
/// Wrappers are removed recursively. The returned command string is a slice of
/// the input, so its original quoting and spacing are preserved for exact-match
/// rules.
pub fn strip_wrappers(subcommand: &str) -> Stripped<'_> {
    let mut command = subcommand.trim();
    loop {
        let tokens = tokenize(command);
        let consumed = wrapper_len(&tokens);
        // Stop if this is not a wrapper, or the wrapper has nothing to wrap.
        if consumed == 0 || consumed >= tokens.len() {
            let argv = tokens.into_iter().map(|t| t.text).collect();
            return Stripped { command, argv };
        }
        command = command[tokens[consumed].start..].trim_end();
    }
}

/// Whether a recognized file command reads or writes the paths it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    Read,
    Write,
}

/// Extract the file paths a recognized file command would touch.
///
/// Returns an empty list when the command is not a recognized file command.
/// The first argument of `sed` is its script rather than a path; it is
/// included anyway because matching a non-path token against a path rule is
/// harmless (it simply never matches), whereas dropping a real path would
/// weaken a deny rule.
pub fn file_command_paths(argv: &[String]) -> Vec<(FileAccess, String)> {
    let Some(first) = argv.first() else {
        return Vec::new();
    };
    let access = match base_name(first) {
        "cat" | "head" | "tail" | "nl" | "od" | "xxd" | "less" | "more" => FileAccess::Read,
        "tee" => FileAccess::Write,
        "sed" => {
            let in_place = argv[1..]
                .iter()
                .any(|a| a == "-i" || a.starts_with("-i") || a.starts_with("--in-place"));
            if in_place {
                FileAccess::Write
            } else {
                FileAccess::Read
            }
        }
        _ => return Vec::new(),
    };
    argv[1..]
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|a| (access, a.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        tokenize(s).into_iter().map(|t| t.text).collect()
    }

    #[test]
    fn tokenize_respects_quotes() {
        assert_eq!(
            argv(r#"echo "hello world" 'a b'"#),
            ["echo", "hello world", "a b"]
        );
        assert_eq!(argv("ls   -la"), ["ls", "-la"]);
    }

    #[test]
    fn split_on_all_operators() {
        assert_eq!(split_compound("a && b || c"), ["a", "b", "c"]);
        assert_eq!(split_compound("a ; b | c"), ["a", "b", "c"]);
        assert_eq!(split_compound("a\nb"), ["a", "b"]);
        assert_eq!(split_compound("a |& b"), ["a", "b"]);
    }

    #[test]
    fn split_ignores_operators_inside_quotes() {
        assert_eq!(split_compound(r#"echo "a && b""#), [r#"echo "a && b""#]);
    }

    #[test]
    fn strip_simple_wrappers() {
        assert_eq!(strip_wrappers("timeout 30 npm test").command, "npm test");
        assert_eq!(
            strip_wrappers("nice -n 10 cargo build").command,
            "cargo build"
        );
        assert_eq!(strip_wrappers("nohup ./run.sh").command, "./run.sh");
        assert_eq!(strip_wrappers("time make").command, "make");
    }

    #[test]
    fn strip_wrappers_recursively() {
        assert_eq!(
            strip_wrappers("timeout 5 nice -n5 npm test").command,
            "npm test"
        );
    }

    #[test]
    fn strip_timeout_with_value_flag() {
        assert_eq!(
            strip_wrappers("timeout -s KILL 30 rm -rf /tmp/x").command,
            "rm -rf /tmp/x"
        );
    }

    #[test]
    fn bare_xargs_is_stripped_but_flagged_xargs_is_not() {
        assert_eq!(strip_wrappers("xargs grep pattern").command, "grep pattern");
        assert_eq!(
            strip_wrappers("xargs -n1 grep pattern").command,
            "xargs -n1 grep pattern"
        );
    }

    #[test]
    fn wrapper_with_nothing_to_wrap_is_left_intact() {
        assert_eq!(strip_wrappers("timeout 30").command, "timeout 30");
    }

    #[test]
    fn recognizes_read_file_commands() {
        let paths = file_command_paths(&argv("cat /etc/passwd /etc/hosts"));
        assert_eq!(
            paths,
            [
                (FileAccess::Read, "/etc/passwd".to_string()),
                (FileAccess::Read, "/etc/hosts".to_string()),
            ]
        );
    }

    #[test]
    fn sed_in_place_is_a_write() {
        let paths = file_command_paths(&argv("sed -i s/a/b/ notes.txt"));
        assert!(paths.iter().all(|(a, _)| *a == FileAccess::Write));
        assert!(paths.iter().any(|(_, p)| p == "notes.txt"));
    }

    #[test]
    fn non_file_command_yields_no_paths() {
        assert!(file_command_paths(&argv("ls -la /etc")).is_empty());
    }
}
