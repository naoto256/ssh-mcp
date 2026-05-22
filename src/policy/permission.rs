//! Parsing and matching of Claude Code permission rules.
//!
//! A rule is `Tool` or `Tool(specifier)`. Bash specifiers follow Claude Code's
//! command grammar (exact, prefix, or wildcard); file-tool specifiers follow
//! the gitignore path grammar. This is a from-scratch implementation faithful
//! to that grammar — see the project design notes for why a third-party crate
//! is referenced but not depended on.

use anyhow::{Result, bail};
use globset::{GlobBuilder, GlobMatcher};
use regex::Regex;

use super::Decision;
use super::command::{FileAccess, file_command_paths, split_compound, strip_wrappers};
use crate::config::Permissions;

/// The tool a rule applies to. Only the tools reachable from a remote command
/// are distinguished; everything else is inert for command evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Bash,
    Read,
    Edit,
    Write,
    /// `WebFetch`, `mcp__*`, `Agent`, and so on — parsed but never matched
    /// against a remote command.
    Other,
}

impl Tool {
    fn parse(name: &str) -> Tool {
        match name.trim() {
            "Bash" => Tool::Bash,
            "Read" => Tool::Read,
            "Edit" => Tool::Edit,
            "Write" => Tool::Write,
            _ => Tool::Other,
        }
    }
}

/// A compiled Bash command specifier.
#[derive(Debug)]
pub enum PermissionPattern {
    /// The whole command must equal this string.
    Exact(String),
    /// The command must start with `prefix`. When `word_boundary` is set, the
    /// next character must be a space or the end of the string — this is the
    /// `:*` / trailing ` *` form.
    Prefix { prefix: String, word_boundary: bool },
    /// A specifier with interior wildcards, compiled to an anchored regex.
    Glob(Regex),
}

impl PermissionPattern {
    /// Compile a non-empty, non-`*` Bash specifier.
    fn compile_bash(spec: &str) -> PermissionPattern {
        // Separate any trailing wildcard from the body. A trailing `:*` or
        // ` *` carries a word boundary; a bare trailing `*` does not.
        let (body, word_boundary) = if let Some(b) = spec.strip_suffix(":*") {
            (b, true)
        } else if let Some(b) = spec.strip_suffix(" *") {
            (b, true)
        } else if let Some(b) = spec.strip_suffix('*') {
            (b, false)
        } else {
            (spec, false)
        };
        let has_trailing_star = spec.ends_with('*');

        if !body.contains('*') {
            return if has_trailing_star {
                PermissionPattern::Prefix {
                    prefix: body.to_string(),
                    word_boundary,
                }
            } else {
                PermissionPattern::Exact(body.to_string())
            };
        }

        // Interior wildcards remain: build an anchored regex. `*` matches any
        // run of characters, including spaces.
        let mut pattern = String::from("^");
        for ch in body.chars() {
            if ch == '*' {
                pattern.push_str(".*");
            } else {
                pattern.push_str(&regex::escape(&ch.to_string()));
            }
        }
        if has_trailing_star {
            if word_boundary {
                pattern.push_str("( .*)?");
            } else {
                pattern.push_str(".*");
            }
        }
        pattern.push('$');
        PermissionPattern::Glob(
            Regex::new(&pattern).expect("a generated command regex is always valid"),
        )
    }

    fn matches(&self, command: &str) -> bool {
        match self {
            PermissionPattern::Exact(p) => command == p,
            PermissionPattern::Prefix {
                prefix,
                word_boundary,
            } => {
                if !command.starts_with(prefix.as_str()) {
                    return false;
                }
                if !word_boundary {
                    return true;
                }
                let rest = &command[prefix.len()..];
                rest.is_empty() || rest.starts_with(' ')
            }
            PermissionPattern::Glob(re) => re.is_match(command),
        }
    }
}

/// Translate a Claude Code path specifier into a gitignore-style glob.
///
/// The remote filesystem has no project root, so `//abs`, `~/home`, and
/// project-relative forms are kept literal and matched as written. A bare
/// filename matches at any depth, per gitignore semantics.
fn normalize_path_pattern(spec: &str) -> String {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix("//") {
        format!("/{rest}")
    } else if spec.starts_with('~') || spec.starts_with('/') || spec.contains('/') {
        spec.to_string()
    } else {
        format!("**/{spec}")
    }
}

fn compile_path(spec: &str) -> Result<GlobMatcher> {
    let pattern = normalize_path_pattern(spec);
    let glob = GlobBuilder::new(&pattern)
        .literal_separator(true)
        .build()
        .map_err(|e| anyhow::anyhow!("invalid path pattern {spec:?}: {e}"))?;
    Ok(glob.compile_matcher())
}

/// How a rule decides whether it applies.
enum RuleMatcher {
    /// Matches every use of the tool (a bare tool name or `Bash(*)`).
    Any,
    Bash(PermissionPattern),
    Path(GlobMatcher),
    /// A tool that cannot be reached from a remote command.
    Inert,
}

/// A single parsed permission rule.
pub struct Permission {
    pub tool: Tool,
    raw: String,
    matcher: RuleMatcher,
}

impl Permission {
    /// Parse one rule string, e.g. `Bash(git push:*)` or `Read(~/.ssh/**)`.
    pub fn parse(rule: &str) -> Result<Permission> {
        let rule = rule.trim();
        let (tool_name, spec) = match rule.find('(') {
            Some(open) => {
                if !rule.ends_with(')') {
                    bail!("malformed permission rule: {rule:?}");
                }
                (&rule[..open], Some(&rule[open + 1..rule.len() - 1]))
            }
            None => (rule, None),
        };
        let tool = Tool::parse(tool_name);

        let matcher = match (tool, spec) {
            (Tool::Other, _) => RuleMatcher::Inert,
            (_, None) => RuleMatcher::Any,
            (Tool::Bash, Some(s)) if s.trim().is_empty() || s.trim() == "*" => RuleMatcher::Any,
            (Tool::Bash, Some(s)) => RuleMatcher::Bash(PermissionPattern::compile_bash(s)),
            (Tool::Read | Tool::Edit | Tool::Write, Some(s))
                if s.trim().is_empty() || s.trim() == "*" =>
            {
                RuleMatcher::Any
            }
            (Tool::Read | Tool::Edit | Tool::Write, Some(s)) => RuleMatcher::Path(compile_path(s)?),
        };

        Ok(Permission {
            tool,
            raw: rule.to_string(),
            matcher,
        })
    }

    /// The original rule string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    fn matches_command(&self, command: &str) -> bool {
        match &self.matcher {
            RuleMatcher::Any => true,
            RuleMatcher::Bash(p) => p.matches(command),
            RuleMatcher::Path(_) | RuleMatcher::Inert => false,
        }
    }

    fn matches_path(&self, path: &str) -> bool {
        match &self.matcher {
            RuleMatcher::Any => true,
            RuleMatcher::Path(g) => g.is_match(path),
            RuleMatcher::Bash(_) | RuleMatcher::Inert => false,
        }
    }
}

fn parse_all(rules: &[String]) -> Result<Vec<Permission>> {
    rules.iter().map(|r| Permission::parse(r)).collect()
}

/// A set of permission rules split into the three precedence lists.
pub struct PermissionSet {
    deny: Vec<Permission>,
    ask: Vec<Permission>,
    allow: Vec<Permission>,
}

impl PermissionSet {
    /// Build a set from the three rule lists, parsing every rule.
    pub fn from_permissions(permissions: &Permissions) -> Result<PermissionSet> {
        Ok(PermissionSet {
            deny: parse_all(&permissions.deny)?,
            ask: parse_all(&permissions.ask)?,
            allow: parse_all(&permissions.allow)?,
        })
    }

    /// Evaluate a remote shell command. The command is split into subcommands,
    /// each is stripped of wrappers and checked, and the most restrictive
    /// subcommand decision is returned.
    pub fn evaluate_command(&self, command: &str) -> Decision {
        let subcommands = split_compound(command);
        if subcommands.is_empty() {
            return Decision::Unset;
        }
        let mut decision = Decision::Allow;
        for sub in &subcommands {
            decision = decision.combine_compound(self.evaluate_subcommand(sub));
        }
        decision
    }

    fn evaluate_subcommand(&self, subcommand: &str) -> Decision {
        let stripped = strip_wrappers(subcommand);
        let paths = file_command_paths(&stripped.argv);
        // Precedence: deny, then ask, then allow.
        if self.any_match(&self.deny, stripped.command, &paths) {
            Decision::Deny
        } else if self.any_match(&self.ask, stripped.command, &paths) {
            Decision::Ask
        } else if self.any_match(&self.allow, stripped.command, &paths) {
            Decision::Allow
        } else {
            Decision::Unset
        }
    }

    fn any_match(
        &self,
        rules: &[Permission],
        command: &str,
        paths: &[(FileAccess, String)],
    ) -> bool {
        rules.iter().any(|rule| match rule.tool {
            Tool::Bash => rule.matches_command(command),
            Tool::Read => paths
                .iter()
                .any(|(access, p)| *access == FileAccess::Read && rule.matches_path(p)),
            Tool::Edit | Tool::Write => paths
                .iter()
                .any(|(access, p)| *access == FileAccess::Write && rule.matches_path(p)),
            Tool::Other => false,
        })
    }

    /// Match a single tool and argument against the three lists. A lower-level
    /// primitive than [`evaluate_command`]: it does no compound splitting or
    /// wrapper stripping, and treats `arg` as a command for `Bash` and as a
    /// path for the file tools.
    pub fn check(&self, tool: Tool, arg: &str) -> Decision {
        let hit = |rules: &[Permission]| {
            rules.iter().any(|rule| match (tool, rule.tool) {
                (Tool::Bash, Tool::Bash) => rule.matches_command(arg),
                (Tool::Read, Tool::Read) => rule.matches_path(arg),
                // A Claude Code `Edit` rule governs writes too, and vice versa.
                (Tool::Edit | Tool::Write, Tool::Edit | Tool::Write) => rule.matches_path(arg),
                _ => false,
            })
        };
        if hit(&self.deny) {
            Decision::Deny
        } else if hit(&self.ask) {
            Decision::Ask
        } else if hit(&self.allow) {
            Decision::Allow
        } else {
            Decision::Unset
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(allow: &[&str], ask: &[&str], deny: &[&str]) -> PermissionSet {
        let to_vec = |s: &[&str]| s.iter().map(|x| x.to_string()).collect();
        PermissionSet::from_permissions(&Permissions {
            allow: to_vec(allow),
            ask: to_vec(ask),
            deny: to_vec(deny),
        })
        .unwrap()
    }

    #[test]
    fn exact_match_only() {
        let s = set(&["Bash(npm run build)"], &[], &[]);
        assert_eq!(s.evaluate_command("npm run build"), Decision::Allow);
        assert_eq!(s.evaluate_command("npm run build --watch"), Decision::Unset);
    }

    #[test]
    fn colon_star_is_a_word_boundary_prefix() {
        let s = set(&["Bash(git push:*)"], &[], &[]);
        assert_eq!(s.evaluate_command("git push"), Decision::Allow);
        assert_eq!(s.evaluate_command("git push origin main"), Decision::Allow);
        assert_eq!(s.evaluate_command("git pushf"), Decision::Unset);
    }

    #[test]
    fn space_star_equals_colon_star() {
        let s = set(&["Bash(ls *)"], &[], &[]);
        assert_eq!(s.evaluate_command("ls -la"), Decision::Allow);
        assert_eq!(s.evaluate_command("ls"), Decision::Allow);
        assert_eq!(s.evaluate_command("lsof"), Decision::Unset);
    }

    #[test]
    fn bare_trailing_star_has_no_word_boundary() {
        let s = set(&["Bash(npm*)"], &[], &[]);
        assert_eq!(s.evaluate_command("npm test"), Decision::Allow);
        assert_eq!(s.evaluate_command("npmfoo"), Decision::Allow);
    }

    #[test]
    fn interior_wildcard_spans_arguments() {
        let s = set(&["Bash(git * main)"], &[], &[]);
        assert_eq!(s.evaluate_command("git checkout main"), Decision::Allow);
        assert_eq!(s.evaluate_command("git push origin main"), Decision::Allow);
        assert_eq!(s.evaluate_command("git push origin"), Decision::Unset);
    }

    #[test]
    fn deny_beats_allow() {
        let s = set(&["Bash(rm:*)"], &[], &["Bash(rm -rf:*)"]);
        assert_eq!(s.evaluate_command("rm -rf /"), Decision::Deny);
        assert_eq!(s.evaluate_command("rm file"), Decision::Allow);
    }

    #[test]
    fn every_subcommand_must_be_allowed() {
        let s = set(&["Bash(echo:*)"], &[], &[]);
        assert_eq!(s.evaluate_command("echo hi"), Decision::Allow);
        assert_eq!(s.evaluate_command("echo hi && rm file"), Decision::Unset);
    }

    #[test]
    fn deny_in_any_subcommand_blocks_the_whole_command() {
        let s = set(&["Bash(echo:*)"], &[], &["Bash(rm:*)"]);
        assert_eq!(s.evaluate_command("echo hi && rm file"), Decision::Deny);
    }

    #[test]
    fn wrappers_are_stripped_before_matching() {
        let s = set(&["Bash(npm test:*)"], &[], &[]);
        assert_eq!(s.evaluate_command("timeout 30 npm test"), Decision::Allow);
    }

    #[test]
    fn read_rules_apply_to_file_commands() {
        let s = set(&[], &[], &["Read(//etc/**)"]);
        assert_eq!(s.evaluate_command("cat /etc/shadow"), Decision::Deny);
        assert_eq!(s.evaluate_command("cat ./notes.txt"), Decision::Unset);
    }

    #[test]
    fn bare_filename_path_rule_matches_any_depth() {
        let s = set(&[], &[], &["Read(.env)"]);
        assert_eq!(s.evaluate_command("cat .env"), Decision::Deny);
        assert_eq!(s.evaluate_command("cat config/.env"), Decision::Deny);
    }

    #[test]
    fn bare_tool_matches_everything() {
        let s = set(&[], &[], &["Bash"]);
        assert_eq!(s.evaluate_command("anything at all"), Decision::Deny);
    }

    #[test]
    fn malformed_rule_is_rejected() {
        assert!(Permission::parse("Bash(unclosed").is_err());
    }
}
