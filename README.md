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
for gated hosts.

## Design

Enforcement lives **outside the model**. The model only proposes a host and a
command; whether it runs is decided by non-model code:

- **`ssh-mcp serve`** — the long-lived MCP server. It owns the host inventory,
  evaluates policy, runs SSH commands, and writes the audit log.
- **`ssh-mcp hook`** — a `PreToolUse` hook that is a pure proxy: it relays the
  request to the server and returns the server's decision. It holds no policy
  logic.

Policy for a host is a set of gates (`free`, `def`, `claude`, `hook`) composed
strictest-wins. The server is the single reader of the inventory; the hook
never reads it.

## Build

```sh
cargo build --release
```

The binary is `ssh-mcp`, with subcommands `serve` and `hook`.

## Status

Early development. The scaffold builds; the policy evaluator, SSH execution
core, MCP server, and hook proxy are being implemented.

## Contributing

- Commit messages are in English and explain the **why**.
- One logical change per commit — no intermediate broken states.
- Work on feature branches; `main` stays releasable.
- `cargo fmt` and `cargo clippy -- -D warnings` must pass before a commit.

## License

Licensed under either of MIT or Apache-2.0 at your option.
