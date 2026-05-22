# ssh-mcp

A policy-gated SSH execution MCP server for Claude Code, written in Rust.

It presents a curated host inventory to the model and runs remote commands
through a per-host policy gate: hosts you are free to use run without a prompt,
hosts that need care run with confirmation or restrictions — each one declared
once, in one file.

## Why

Claude Code can be run with a broad permission bypass, delegating control to a
`PreToolUse` hook plus `permissions.*` rules. SSH does not fit that model well:
every SSH target requires a confirmation prompt, even lab machines you are
happy to let the agent use freely, and the purpose of each host has to be
re-explained every session.

`ssh-mcp` moves SSH execution off the `Bash` tool onto a structured MCP tool.
The model reads the inventory itself via `list_hosts`, picks a host, and calls
`exec`. A per-host policy decides — without a prompt for free hosts, with one
for gated hosts. `get_file` and `put_file` move files and directories the same
way, under the same policy.

## Design

Enforcement lives **outside the model**. The model only proposes a host and a
command; whether it runs is decided by non-model code. ssh-mcp is one binary
with three subcommands:

- **`ssh-mcp daemon`** — the resident server, shared by every Claude Code
  session. It owns the host inventory, the SSH connection pool, policy
  evaluation, and the audit log.
- **`ssh-mcp serve`** — the MCP server the harness spawns per session. It is a
  thin shim that relays bytes between the harness and the daemon; it speaks no
  MCP itself.
- **`ssh-mcp hook`** — a `PreToolUse` hook, a pure proxy that forwards a policy
  query to the daemon and returns its decision. It holds no policy logic.

The shim and the hook reach the daemon over Unix sockets under
`~/.ssh/ssh-mcp/` — there is no TCP port and no network surface. The sockets
are owner-only, and the daemon checks each connection's peer credentials.

A host's `policy` is a set of gates (`free`, `def`, `claude`, `hook`) composed
strictest-wins. The daemon is the single reader of the inventory.

File transfer streams a `tar` archive over the SSH connection, carrying files
and directories alike. A transfer is gated on both paths it touches: the
remote path by the host's policy, the local path by your own Claude Code file
rules, whichever is stricter.

## Build

```sh
cargo build --release
```

The binary is `ssh-mcp`, with subcommands `daemon`, `serve`, and `hook`.
Install it somewhere stable, for example:

```sh
cp target/release/ssh-mcp ~/.local/bin/ssh-mcp
```

## Setup

Three things need wiring (macOS with Claude Code).

### 1. The host inventory

Describe your hosts in `~/.ssh/ssh-mcp.toml`:

```toml
# Each exec has a time limit, 600s by default. Override it globally here, or
# per host with an exec_timeout_secs key under [hosts.<alias>].
[defaults]
exec_timeout_secs = 600

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

`free` runs without a prompt; `def` applies the rules written inline under
`[hosts.<alias>.def]`; `claude` applies the rules from `~/.claude/settings.json`;
`{ hook = "..." }` delegates to an external hook program. Each host must
already be in `~/.ssh/known_hosts`, and your SSH agent must hold a key it
accepts.

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
      { "matcher": "mcp__ssh__(exec|get_file|put_file)",
        "hooks": [ { "type": "command", "command": "<path>/ssh-mcp hook" } ] }
    ]
  }
}
```

- The matcher covers `exec`, `get_file`, and `put_file` — every tool that acts
  on a host. `list_hosts` is read-only and ungated.
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

## Contributing

- Commit messages are in English and explain the **why**.
- One logical change per commit — no intermediate broken states.
- Work on feature branches; `main` stays releasable.
- `cargo fmt` and `cargo clippy -- -D warnings` must pass before a commit.

## License

Licensed under either of MIT or Apache-2.0 at your option.
