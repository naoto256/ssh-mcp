# ssh-mcp

[![CI](https://github.com/naoto256/ssh-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/naoto256/ssh-mcp/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Release](https://img.shields.io/github/v/release/naoto256/ssh-mcp?sort=semver)](https://github.com/naoto256/ssh-mcp/releases)

A policy-gated SSH execution MCP server for Claude Code and Codex, written in
Rust.

It presents a curated host inventory to the model and runs remote commands and
file transfers through a per-host policy gate: hosts you are free to use run
without a prompt, hosts that need care run with confirmation or restrictions —
each one declared once, in one file.

The design rationale lives in [DESIGN.md](DESIGN.md); this file covers what
you need to get it running.

## Why

Claude Code and Codex can both run external tools through MCP servers and
host-side policy hooks. Raw SSH does not fit that model well: every SSH target
needs its own trust decision, even lab machines you are happy to let the agent
use freely, and the purpose of each host has to be re-explained every session.

`ssh-mcp` moves SSH execution off the `Bash` tool onto structured MCP tools.
The model reads the inventory itself via `list_hosts`, picks a host, and calls
a tool. A per-host policy decides — without a prompt for free hosts, with one
for gated hosts. The same gate covers command execution and file transfer.

## Tools

The MCP server exposes nine tools. All of them except `list_hosts`,
`list_agent_keys`, `trace`, and `propose_host` take a `host` argument
that must be an alias from `list_hosts`.

| Tool | What it does |
|---|---|
| `list_hosts` | Returns each host's alias, purpose, tags, and policy kinds — **never** an address, user, or credential. Read-only, ungated. |
| `exec` | Runs a shell command on a host and returns the exit code, line counts, and (optionally) the scoped output. The `op` parameter is an ordered pipeline of steps; omit it or pass `[]` to get metadata only (the body stays in the per-session trace buffer for inspection via `trace`). To get the body inline, pass at least one step: `[{full: true}]` for everything, `[{tail: 50}]` for the last 50, or chain like `[{head: 100}, {tail: 50}, {grep: "err"}]`. Piping the command through `tail` / `head` / `grep` yourself defeats the trace path; the daemon spots that and returns an advisory `note` on the result. |
| `get` | Downloads a file or directory. If the local destination is an existing directory the entry lands inside it under its remote base name (the `cp` rule); otherwise it replaces the destination. Returns wire bytes (tar framing + metadata, not the sum of file content sizes). |
| `put` | Symmetric: uploads a local file or directory. If the remote destination is an existing directory the entry lands inside; otherwise it replaces. Returns wire bytes (same meaning as `get`). |
| `sync_get` / `sync_put` | Mirror a directory in either direction. Both paths are treated as roots: files in the destination that are absent from the source are deleted; files matching by sha-256 are skipped. Returns per-op counts and the wire bytes for the files that actually moved. |
| `trace` | Re-inspects the full detail of a recent tool call from a per-session ring buffer (depth 5, 10 MiB per entry). `op` is the same pipeline shape as `exec`, but required (at least one step — pass `[{full: true}]` for the whole body). Accepts a `stream` selector (`stdout` / `stderr` / `both`, default `both`) for exec entries. `grep` matches the bare line text, so a pattern that worked on the original `exec` result keeps working. Transfer entries come back as `<verb> <path>` lines. |
| `propose_host` | Appends a *pending* host entry to the daemon-owned ephemeral inventory next to `ssh-mcp.toml` (for the default config, `~/.ssh/ssh-mcp.ephem.toml`) for a freshly spun-up cloud VM or similar. The entry is written with `disabled = true` plus an `expires_at` (required, RFC 3339, at most 30 days out) and a pinned `host_key` (required, OpenSSH single-line public key); **the user has to open the TOML and remove the `disabled` line for the host to become usable** — that hand edit is the trust gate. The server picks the alias (`tmp-` + 6 random hex chars) and hard-codes `policy = ["claude"]`; the input supplies `hostname`, `user`, `purpose`, `expires_at`, `host_key`, plus the optional `port`, `tags`, `proxy_jump`. The pinned `host_key` lets the entry skip `~/.ssh/known_hosts` entirely — verification is byte-match against the pin. Returns the alias, the absolute ephemeral config path, the appended TOML snippet, and a short activation hint to echo to the user. Example: `{"hostname": "13.78.10.5", "user": "azureuser", "purpose": "azure scratch box", "expires_at": "2026-05-27T19:30:00+09:00", "host_key": "ssh-ed25519 AAAAC3Nz... host@vm"}`. |
| `list_agent_keys` | Lists the public keys held by the SSH agent (`$SSH_AUTH_SOCK`). Equivalent to `ssh-add -L`. Use it to tell the user which key to drop into a freshly provisioned host's `authorized_keys` (paste the `public_key` string), or to diagnose "SSH agent authentication failed" exec failures. Returns `type` / `comment` / `fingerprint` (SHA-256) / full OpenSSH `public_key` per identity. No arguments. Certificates are not included. |

The `op` pipeline on `exec` and `trace` exists so scoping happens through the
tool, not through `tail` / `head` / `grep` pipes in the shell command itself
— the latter throws away the exact bytes `trace` would have shown. The
pipeline shape lets the model compose narrowing steps (`[{head: 100},
{tail: 50}]` is a sliding window from line 51 to 100) and surfaces a clear
"give me nothing" default on `exec` (omit `op` to keep result context-light
and pull what you need later through `trace`).

## Install

Choose the installation path that matches the host running Claude Code or Codex.
Windows is not currently supported as a daemon host; use WSL2 if you need to
drive ssh-mcp from a Windows machine.

### Homebrew (macOS arm64)

```sh
brew tap naoto256/ssh-mcp
brew install ssh-mcp
brew services start ssh-mcp
```

### Cargo (Rust users, macOS or Linux)

```sh
cargo install ssh-mcp
```

### Debian / Ubuntu (.deb, Linux x86_64)

Download `ssh-mcp_0.3.0-1_amd64.deb` from
[GitHub Releases](https://github.com/naoto256/ssh-mcp/releases), then:

```sh
sudo dpkg -i ssh-mcp_0.3.0-1_amd64.deb
systemctl --user enable --now ssh-mcp
```

### Source build (advanced / contributors)

```sh
cargo build --release
```

The binary is `ssh-mcp`, with subcommands `daemon`, `serve`, and `hook`.
Install it somewhere stable:

```sh
cp target/release/ssh-mcp ~/.local/bin/ssh-mcp
```

## Setup

Four things need wiring for a full Claude Code or Codex setup. Some install
paths above already start the daemon; the remaining steps are the same. Windows
is not currently supported **as a host for the daemon** — the daemon uses Unix
Domain Sockets with peer-uid checks for its control channel; the equivalent on
Windows would need a Named Pipe transport that has not been ported yet. Use WSL2
if you need to drive ssh-mcp from a Windows machine.

**Remote hosts** can be POSIX or Windows. The daemon probes each
connection's shell family at connect time, picks the right command shapes
on the fly (POSIX uses `find` / `sha256sum` / `tar`; Windows uses
PowerShell + `tar.exe` and `Get-FileHash`), and decodes the remote console
encoding (UTF-8 for POSIX, whatever `chcp` reports for Windows — e.g.
CP932 on Japanese installs) before handing text back to the caller.

### 1. The host inventory

Describe permanent hosts in `~/.ssh/ssh-mcp.toml`:

```sh
ssh-mcp import > ~/.ssh/ssh-mcp.toml
```

The import command reads `~/.ssh/config`, asks OpenSSH to resolve each concrete
host alias, and prints a reviewable `ssh-mcp.toml` skeleton. It never writes the
file in place.

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

# Shared rulesets, referenced by `{ def = "name" }` in any host's policy.
[def.company-baseline]
deny = ["Bash(rm -rf:*)", "Bash(dd:*)"]

[hosts.staging-other]
hostname = "10.0.2.9"
user     = "deploy"
purpose  = "Another staging host with shared baseline + extra restrict"
policy   = [{ def = "company-baseline" }, "claude"]
```

Three optional fields on every host entry control ephemerality and host-key trust:

| Field | Effect |
|---|---|
| `expires_at` | RFC 3339 datetime (e.g. `2026-05-27T19:30:00+09:00`). When the daemon next loads the inventory, any host whose `expires_at` has passed is removed from the in-memory inventory. Expired entries in the daemon-owned ephemeral file are also removed from that file on disk; the main `ssh-mcp.toml` is treated as read-only daemon input. |
| `disabled` | Boolean, default `false`. When `true` the entry is parsed but skipped — it does not appear in `list_hosts` and `exec` (and friends) fail with "unknown host". This is the activation gate `propose_host` uses; flip it to `false` (or delete the line) by hand to enable a pending entry. |
| `host_key` | Pinned host public key in OpenSSH single-line format (e.g. `ssh-ed25519 AAAA... comment`). When set, the daemon verifies the live server key against this value on connect and **skips `~/.ssh/known_hosts` entirely** — a clean fit for ephemeral cloud VMs whose key the user already harvested out-of-band (cloud console, `ssh-keyscan`, etc.). `propose_host` writes this automatically; you can also pin a permanent host by hand. |

A host's `policy` is a set of gates composed strictest-wins:

| Gate | What it does |
|---|---|
| `free` | Allow without prompt. Use for hosts you trust the agent on. |
| `def` | Apply the rules written inline under `[hosts.<alias>.def]` (anonymous, host-local). |
| `{ def = "name" }` | Apply the rules from a top-level `[def.<name>]` table, shared across hosts. Reference the same name from multiple hosts to reuse the ruleset. |
| `claude` | Apply the Claude Code user-level rules from `~/.claude/settings.json`. This gate name is historical; Codex users normally rely on the bundled plugin hook/settings instead of this file. |
| `{ hook = "..." }` | Delegate to an external `PreToolUse` hook program. |

A host's policy can mix any number of gates; the strictest decision wins
(`deny > ask > allow`). An empty list — or omitting `policy` entirely — is
equivalent to `free`. Multiple `{ def = "name" }` references stack — the
strictest of all the referenced rulesets wins.

Each host with no pinned `host_key` must already be in `~/.ssh/known_hosts`
(entries that set `host_key` verify against the pin and skip `known_hosts`
— `propose_host` writes that entry to the sibling ephemeral file). Either way your SSH agent must hold a
key the host accepts. `proxy_jump` is supported: list jump-host aliases
nearest-hop first.

### 2. The daemon

The daemon must be resident, running as your own user. It listens on two
Unix sockets under `~/.ssh/ssh-mcp/`: `mcp.sock` for MCP sessions and
`control.sock` for policy queries. Both are owner-only and the daemon
verifies each connection's peer uid; there is no TCP port and no network
surface.

**macOS** — run it as a LaunchAgent. Edit the binary path in
[`contrib/ssh-mcp-daemon.plist`](contrib/ssh-mcp-daemon.plist), then:

```sh
cp contrib/ssh-mcp-daemon.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/ssh-mcp-daemon.plist
```

If the daemon cannot find the SSH agent, set `SSH_AUTH_SOCK` under
`EnvironmentVariables` in the plist.

**Linux** — run it as a user systemd service. Use
[`contrib/ssh-mcp-daemon.service`](contrib/ssh-mcp-daemon.service):

```sh
mkdir -p ~/.config/systemd/user
cp contrib/ssh-mcp-daemon.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ssh-mcp-daemon
```

If the daemon cannot find the SSH agent, uncomment one of the
`Environment=SSH_AUTH_SOCK=...` lines in the unit (or set your own) and
`systemctl --user restart ssh-mcp-daemon`. Logs are in
`journalctl --user -u ssh-mcp-daemon`.

### 3. Plugin install (Claude Code / Codex)

The in-tree [`plugin/`](plugin/) directory packages the MCP server definition,
the `PreToolUse` policy hook, and host-runtime settings defaults for both
Claude Code and Codex. The plugin keeps the MCP server definition shared in
`plugin/.mcp.json` and resolves the `ssh-mcp` binary through `PATH` by default.
Set `SSH_MCP_BIN` if your host runtime needs an absolute binary path.

Claude Code:

```text
/plugin marketplace add naoto256/ssh-mcp
/plugin install ssh-mcp@naoto256-ssh-mcp
```

Codex:

```sh
codex plugin marketplace add naoto256/ssh-mcp
codex plugin add ssh-mcp@naoto256-ssh-mcp
```

See [`plugin/README.md`](plugin/README.md) for local-checkout installation,
Codex marketplace details, and migration notes from manual host configuration.
After installing, review and trust the bundled hook in the host runtime before
removing your manual `ssh` MCP server or hook entries.

### 4. Manual Claude Code configuration (CC-specific)

If you are using Claude Code without the plugin, register the MCP server and
wire the policy hook by hand. Codex users should prefer the plugin flow above;
its command syntax and settings surface differ from Claude Code's
`~/.claude.json` / `~/.claude/settings.json` files.

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
  `Edit(~/.ssh/ssh-mcp.ephem.toml)`, `Edit(~/.ssh/ssh-mcp/**)`,
  `Edit(~/.claude/settings.json)`, `Edit(~/.claude.json)`, and the path of the
  `ssh-mcp` binary to `permissions.ask` (or `deny`).

## Troubleshooting

**`exec` fails with "no route to host" (`EHOSTUNREACH`) for a host on your
LAN.** On macOS, a process that connects to private/LAN addresses needs Local
Network permission, and a daemon started by launchd may not have been granted
it. Grant it under System Settings → Privacy & Security → Local Network, then
restart the daemon. A host on the public internet, or one reached only through
a public-IP bastion, is not affected.

**A tool call returns "an op step needs exactly one of full=true, head,
tail, or grep" or "trace requires at least one op step".** That is `exec`
/ `trace` rejecting a malformed or empty `op`. `op` is an array of steps;
each step picks one of `{full: true}` / `{head: N}` / `{tail: N}` /
`{grep: STR}`. Combine across steps, not within: `[{head: 100}, {tail: 50}]`
is a sliding window, `{head: 100, tail: 50}` is an error. `exec` accepts
an omitted or empty op (returns metadata only, body stays in trace); `trace`
needs at least one step.

**Slow `sync_*` on a tree you have not touched.** Mirror still walks both
sides and hashes every file. For a 10 k file tree the hash cost is a few
seconds. Use `exclude` for build output and VCS metadata you do not want to
weigh.

## Contributing

This is a personal project. Bug reports and feature requests are welcome via
GitHub Issues; pull requests are not accepted at this time. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
