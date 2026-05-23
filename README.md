# ssh-mcp

A policy-gated SSH execution MCP server for Claude Code, written in Rust.

It presents a curated host inventory to the model and runs remote commands and
file transfers through a per-host policy gate: hosts you are free to use run
without a prompt, hosts that need care run with confirmation or restrictions —
each one declared once, in one file.

The design rationale lives in [DESIGN.md](DESIGN.md); this file covers what
you need to get it running.

## Why

Claude Code can be run with a broad permission bypass, delegating control to a
`PreToolUse` hook plus `permissions.*` rules. SSH does not fit that model well:
every SSH target requires a confirmation prompt, even lab machines you are
happy to let the agent use freely, and the purpose of each host has to be
re-explained every session.

`ssh-mcp` moves SSH execution off the `Bash` tool onto structured MCP tools.
The model reads the inventory itself via `list_hosts`, picks a host, and calls
a tool. A per-host policy decides — without a prompt for free hosts, with one
for gated hosts. The same gate covers command execution and file transfer.

## Tools

The MCP server exposes six tools. All of them take a `host` argument that
must be an alias from `list_hosts`.

| Tool | What it does |
|---|---|
| `list_hosts` | Returns each host's alias, purpose, tags, and policy kinds — **never** an address, user, or credential. Read-only, ungated. |
| `exec` | Runs a shell command on a host and returns the exit code with scoped stdout/stderr. Requires an `op` (`tail` / `head` / `grep`) so output stays deliberately scoped; the full streams are kept in the per-session trace buffer for re-inspection. |
| `get` | Downloads a file or directory. If the local destination is an existing directory the entry lands inside it under its remote base name (the `cp` rule); otherwise it replaces the destination. Returns a byte count. |
| `put` | Symmetric: uploads a local file or directory. If the remote destination is an existing directory the entry lands inside; otherwise it replaces. Returns a byte count. |
| `sync_get` / `sync_put` | Mirror a directory in either direction. Both paths are treated as roots: files in the destination that are absent from the source are deleted; files matching by sha-256 are skipped. Returns per-op counts. |
| `trace` | Re-inspects the full detail of a recent tool call from a per-session ring buffer (depth 5, 10 MiB per entry). Requires an `op`. Transfer entries come back as `<verb> <path>` lines so they grep cleanly. |

The `op` requirement on `exec` and `trace` is deliberate. Models reading the
schema know to scope output through the tool, not by piping through
`tail` / `head` / `grep` in the command itself — the latter throws away the
exact bytes `trace` would have shown.

## Build

```sh
cargo build --release
```

The binary is `ssh-mcp`, with subcommands `daemon`, `serve`, and `hook`.
Install it somewhere stable:

```sh
cp target/release/ssh-mcp ~/.local/bin/ssh-mcp
```

## Setup

Three things need wiring (macOS with Claude Code).

### 1. The host inventory

Describe your hosts in `~/.ssh/ssh-mcp.toml`:

```toml
# Each exec has a time limit, 600s by default. Override globally here, or
# per host with an exec_timeout_secs key under [hosts.<alias>].
[defaults]
exec_timeout_secs = 600
# Globs put / sync_put leave out of an upload, matched against any
# name in the tree. The get / sync_get exclude is set per host, with
# an exclude key under a host.
exclude = ["target", ".git", "node_modules"]

[hosts.build-rig]
hostname = "10.0.5.12"
user     = "ci"
purpose  = "Linux build server"
tags     = ["build"]
policy   = ["free"]

[hosts.staging-api]
hostname = "10.0.2.8"
user     = "deploy"
purpose  = "Staging API host"
tags     = ["api"]
policy   = ["def"]
[hosts.staging-api.def]
allow = ["Bash(systemctl status:*)"]
ask   = ["Bash(systemctl restart:*)"]
deny  = ["Bash(rm:*)"]
```

A host's `policy` is a set of gates composed strictest-wins:

| Gate | What it does |
|---|---|
| `free` | Allow without prompt. Use for hosts you trust the agent on. |
| `def` | Apply the rules written inline under `[hosts.<alias>.def]`. |
| `claude` | Apply the rules from `~/.claude/settings.json` (user-level). |
| `{ hook = "..." }` | Delegate to an external `PreToolUse` hook program. |

A host's policy can mix any number of gates; the strictest decision wins
(`deny > ask > allow`). An empty list — or omitting `policy` entirely — is
equivalent to `free`.

Each host must already be in `~/.ssh/known_hosts`, and your SSH agent must
hold a key it accepts. `proxy_jump` is supported: list jump-host aliases
nearest-hop first.

### 2. The daemon

The daemon must be resident. On macOS, run it as a LaunchAgent — edit the
binary path in [`contrib/ssh-mcp-daemon.plist`](contrib/ssh-mcp-daemon.plist),
then:

```sh
cp contrib/ssh-mcp-daemon.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/ssh-mcp-daemon.plist
```

The daemon needs `SSH_AUTH_SOCK` to reach your SSH agent; if it cannot find
the agent, set it in the plist's `EnvironmentVariables`.

The daemon listens on two Unix sockets under `~/.ssh/ssh-mcp/`:
`mcp.sock` for MCP sessions and `control.sock` for policy queries.
Both are owner-only and the daemon verifies each connection's peer uid;
there is no TCP port and no network surface.

### 3. Claude Code

Two parts: register the MCP server, then wire the policy hook.

Register the server at user scope (available in every project):

```sh
claude mcp add --scope user ssh <path>/ssh-mcp serve
```

This writes the definition to `~/.claude.json`. For a single project, drop a
`.mcp.json` at the project root instead. Claude Code does **not** read
`mcpServers` from `settings.json` — server definitions live only in
`~/.claude.json` or `.mcp.json`.

The harness applies its own per-call timeout to every MCP tool call. Make sure
it is at least as long as the largest `exec_timeout_secs` in your inventory, so
the daemon's own timeout fires first and returns a clean error instead of the
harness cutting the call off. Set it with a `timeout` field (milliseconds) on
the `ssh` entry in `~/.claude.json`.

Then add the PreToolUse hook to `~/.claude/settings.json`:

```jsonc
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "mcp__ssh__(exec|get|put|sync_get|sync_put)",
        "hooks": [ { "type": "command", "command": "<path>/ssh-mcp hook" } ] }
    ]
  }
}
```

- The matcher covers every tool that acts on a host. `list_hosts` is
  read-only and `trace` only reads in-memory session state, so neither is
  gated.
- Do **not** put those tool names in any `permissions` list. The hook is the
  only policy gate; a native `ask` rule would fire even when the hook allows,
  so free hosts would still be prompted.
- Keep `Bash(ssh *)` in `permissions.ask` so raw `ssh` from the `Bash` tool is
  not a bypass.
- Protect the trust root by denying edits to it: add `Edit(~/.ssh/ssh-mcp.toml)`,
  `Edit(~/.ssh/ssh-mcp/**)`, `Edit(~/.claude/settings.json)`, `Edit(~/.claude.json)`,
  and the path of the `ssh-mcp` binary to `permissions.ask` (or `deny`).

## Troubleshooting

**`exec` fails with "no route to host" (`EHOSTUNREACH`) for a host on your
LAN.** On macOS, a process that connects to private/LAN addresses needs Local
Network permission, and a daemon started by launchd may not have been granted
it. Grant it under System Settings → Privacy & Security → Local Network, then
restart the daemon. A host on the public internet, or one reached only through
a public-IP bastion, is not affected.

**A tool call returns "op requires at least one of grep, head, or tail".**
That is `exec` or `trace` rejecting an unscoped request. Pass an op
(`{"tail": 50}`, `{"grep": "error"}`, `{"head": 20}`, or `grep` combined with
one of `head`/`tail`). The intent is to make scoping deliberate.

**Slow `sync_*` on a tree you have not touched.** Mirror still walks both
sides and hashes every file. For a 10 k file tree the hash cost is a few
seconds. Use `exclude` for build output and VCS metadata you do not want to
weigh.

## Contributing

- Commit messages are in English and explain the **why**.
- One logical change per commit — no intermediate broken states.
- Work on feature branches; `main` stays releasable.
- `cargo fmt` and `cargo clippy -- -D warnings` must pass before a commit.

## License

Licensed under either of MIT or Apache-2.0 at your option.
