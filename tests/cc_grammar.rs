//! End-to-end coverage of the Claude Code permission grammar, exercised
//! through the public evaluator API.

use ssh_mcp::config::{HostsConfig, Permissions};
use ssh_mcp::policy::{Decision, Evaluator, PermissionSet, Tool};
use std::path::PathBuf;

/// Build a rule set from the three lists.
fn rules(allow: &[&str], ask: &[&str], deny: &[&str]) -> PermissionSet {
    let to_vec = |s: &[&str]| s.iter().map(|x| x.to_string()).collect();
    PermissionSet::from_permissions(&Permissions {
        allow: to_vec(allow),
        ask: to_vec(ask),
        deny: to_vec(deny),
    })
    .expect("rules should parse")
}

#[test]
fn exact_match_requires_the_whole_command() {
    let s = rules(&["Bash(npm run build)"], &[], &[]);
    assert_eq!(s.evaluate_command("npm run build"), Decision::Allow);
    assert_eq!(s.evaluate_command("npm run build x"), Decision::Unset);
    assert_eq!(s.evaluate_command("npm run buil"), Decision::Unset);
}

#[test]
fn colon_star_and_space_star_are_equivalent() {
    let colon = rules(&["Bash(git push:*)"], &[], &[]);
    let space = rules(&["Bash(git push *)"], &[], &[]);
    for cmd in ["git push", "git push origin main", "git pushf", "git pus"] {
        assert_eq!(
            colon.evaluate_command(cmd),
            space.evaluate_command(cmd),
            "`:*` and ` *` disagree on {cmd:?}"
        );
    }
}

#[test]
fn word_boundary_prefix_does_not_match_a_longer_word() {
    let s = rules(&["Bash(curl:*)"], &[], &[]);
    assert_eq!(s.evaluate_command("curl https://x"), Decision::Allow);
    assert_eq!(s.evaluate_command("curl"), Decision::Allow);
    assert_eq!(s.evaluate_command("curlfoo"), Decision::Unset);
}

#[test]
fn bare_trailing_star_matches_across_a_word_boundary() {
    let s = rules(&["Bash(ls*)"], &[], &[]);
    assert_eq!(s.evaluate_command("ls -la"), Decision::Allow);
    assert_eq!(s.evaluate_command("lsof"), Decision::Allow);
}

#[test]
fn interior_wildcards_span_arguments() {
    let s = rules(&["Bash(* --version)"], &[], &[]);
    assert_eq!(s.evaluate_command("git --version"), Decision::Allow);
    assert_eq!(s.evaluate_command("cargo build --version"), Decision::Allow);
    assert_eq!(s.evaluate_command("git --help"), Decision::Unset);
}

#[test]
fn precedence_is_deny_then_ask_then_allow() {
    let s = rules(
        &["Bash(git:*)"],
        &["Bash(git push:*)"],
        &["Bash(git push --force:*)"],
    );
    assert_eq!(s.evaluate_command("git status"), Decision::Allow);
    assert_eq!(s.evaluate_command("git push origin"), Decision::Ask);
    assert_eq!(
        s.evaluate_command("git push --force origin"),
        Decision::Deny
    );
}

#[test]
fn each_subcommand_of_a_compound_is_checked_independently() {
    let s = rules(&["Bash(echo:*)", "Bash(ls:*)"], &[], &[]);
    assert_eq!(s.evaluate_command("echo hi && ls"), Decision::Allow);
    assert_eq!(s.evaluate_command("echo hi && whoami"), Decision::Unset);
}

#[test]
fn the_strictest_subcommand_decides_a_compound() {
    let s = rules(&["Bash(echo:*)"], &["Bash(ls:*)"], &["Bash(rm:*)"]);
    assert_eq!(s.evaluate_command("echo a && ls"), Decision::Ask);
    assert_eq!(s.evaluate_command("echo a && rm b"), Decision::Deny);
    assert_eq!(s.evaluate_command("echo a ; ls ; rm b"), Decision::Deny);
}

#[test]
fn every_documented_plain_wrapper_is_stripped() {
    let s = rules(&["Bash(make:*)"], &[], &[]);
    for wrapped in [
        "timeout 60 make",
        "timeout -s KILL 60 make",
        "nice make",
        "nice -n 10 make",
        "nohup make",
        "time make",
        "stdbuf -oL make",
        "xargs make",
    ] {
        assert_eq!(
            s.evaluate_command(wrapped),
            Decision::Allow,
            "wrapper not stripped: {wrapped:?}"
        );
    }
}

#[test]
fn xargs_with_flags_is_not_stripped() {
    let s = rules(&["Bash(grep:*)"], &[], &[]);
    assert_eq!(s.evaluate_command("xargs grep x"), Decision::Allow);
    assert_eq!(s.evaluate_command("xargs -n1 grep x"), Decision::Unset);
}

#[test]
fn a_deny_still_fires_through_a_wrapper() {
    let s = rules(&[], &[], &["Bash(rm:*)"]);
    assert_eq!(
        s.evaluate_command("timeout 5 rm -rf /tmp/x"),
        Decision::Deny
    );
    assert_eq!(
        s.evaluate_command("nice -n 5 rm -rf /tmp/x"),
        Decision::Deny
    );
}

#[test]
fn read_rules_apply_to_recognized_file_commands() {
    let s = rules(&[], &[], &["Read(~/.ssh/**)"]);
    assert_eq!(s.evaluate_command("cat ~/.ssh/id_rsa"), Decision::Deny);
    assert_eq!(
        s.evaluate_command("head -n 5 ~/.ssh/config"),
        Decision::Deny
    );
    assert_eq!(s.evaluate_command("cat ~/notes.txt"), Decision::Unset);
}

#[test]
fn edit_rules_apply_to_in_place_and_writing_file_commands() {
    let s = rules(&[], &[], &["Edit(//etc/**)"]);
    assert_eq!(
        s.evaluate_command("sed -i s/a/b/ /etc/hosts"),
        Decision::Deny
    );
    assert_eq!(s.evaluate_command("tee /etc/motd"), Decision::Deny);
}

#[test]
fn the_low_level_check_matches_a_single_tool_and_argument() {
    let s = rules(&["Bash(ls:*)"], &[], &["Read(/secret)"]);
    assert_eq!(s.check(Tool::Bash, "ls -la"), Decision::Allow);
    assert_eq!(s.check(Tool::Read, "/secret"), Decision::Deny);
    assert_eq!(s.check(Tool::Bash, "/secret"), Decision::Unset);
}

#[test]
fn gate_composition_merges_def_and_claude_then_takes_the_strictest() {
    // The claude gate finds no settings file, so only `def` contributes here.
    let evaluator = Evaluator::with_claude_settings_path(PathBuf::from("/nonexistent.json"));
    let config = HostsConfig::parse(
        r#"
        [hosts.api]
        hostname = "h"
        purpose  = "p"
        policy   = ["def"]
        [hosts.api.def]
        allow = ["Bash(systemctl status:*)"]
        ask   = ["Bash(systemctl restart:*)"]
        deny  = ["Bash(rm:*)"]
    "#,
    )
    .unwrap();

    assert_eq!(
        evaluator
            .evaluate(&config, "api", "systemctl status nginx")
            .unwrap(),
        Decision::Allow
    );
    assert_eq!(
        evaluator
            .evaluate(&config, "api", "systemctl restart nginx")
            .unwrap(),
        Decision::Ask
    );
    assert_eq!(
        evaluator.evaluate(&config, "api", "rm -rf /").unwrap(),
        Decision::Deny
    );
    assert_eq!(
        evaluator.evaluate(&config, "api", "uptime").unwrap(),
        Decision::Deny // no rule matched: fail closed
    );
}

#[test]
fn an_empty_policy_behaves_like_free() {
    let evaluator = Evaluator::with_claude_settings_path(PathBuf::from("/nonexistent.json"));
    let config = HostsConfig::parse(
        r#"
        [hosts.open]
        hostname = "h"
        purpose  = "p"
        policy   = []
    "#,
    )
    .unwrap();
    assert_eq!(
        evaluator.evaluate(&config, "open", "rm -rf /").unwrap(),
        Decision::Allow
    );
}
