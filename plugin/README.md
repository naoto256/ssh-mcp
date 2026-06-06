# ssh-mcp Plugin

This plugin wires `ssh-mcp` into Claude Code and Codex as a bundled MCP server
plus the matching `PreToolUse` policy hook.

## What it does

- **MCP server registration** (`.mcp.json`). Adds the `ssh` MCP server over
  stdio with `ssh-mcp serve`.
- **Policy hook** (`hooks/hooks.json` -> `tools/ssh-mcp-hook.sh`). Routes
  host-affecting MCP tool calls (`exec`, `get`, `put`, `sync_get`, `sync_put`)
  through `ssh-mcp hook`, which asks the resident daemon for the strictest
  policy decision.
- **Claude Code settings defaults** (`settings.json`). Protects the
  `ssh-mcp` trust-root files from agent edits, asks before raw `ssh` from
  `Bash`, and asks before edits to the default `~/.local/bin/ssh-mcp` binary.

The hook deliberately does not gate `list_hosts`, `list_agent_keys`, `trace`,
or `propose_host`: those tools are read-only, inspect session-local state, or
write only disabled pending host entries that require a later manual edit.

## Prerequisites

- `ssh-mcp daemon` is running as your user.
- `ssh-mcp` is available on the host runtime `PATH`.

If the host runtime does not inherit your shell `PATH`, set `SSH_MCP_BIN` to an
absolute binary path before starting the host app, or edit `plugin/.mcp.json`
during local development.

## Claude Code

From a published GitHub remote:

```text
/plugin marketplace add naoto256/ssh-mcp
/plugin install ssh-mcp@naoto256-ssh-mcp
```

From a local checkout:

```text
/plugin marketplace add /absolute/path/to/ssh-mcp
/plugin install ssh-mcp@naoto256-ssh-mcp
```

Restart the Claude Code session after installing so the MCP server, hook, and
settings defaults are loaded. The standard hook trust review still applies.

## Codex

Add the repo marketplace and install the plugin:

```sh
codex plugin marketplace add /absolute/path/to/ssh-mcp
codex plugin add ssh-mcp@naoto256-ssh-mcp
```

Then restart Codex. Codex reads the plugin from
`plugin/.codex-plugin/plugin.json`, the shared `plugin/.mcp.json`, and
`plugin/hooks/hooks.json`.

Codex plugin hooks are non-managed hooks, so Codex will skip them until you
review and trust the current hook definition.

## Migrating from manual configuration

Remove the manual `ssh` MCP server entry and manual `PreToolUse` hook only
after the plugin has been installed and trusted.

Manual Claude Code entries that this plugin replaces:

```jsonc
{
  "mcpServers": {
    "ssh": {
      "type": "stdio",
      "command": "<path>/ssh-mcp",
      "args": ["serve"],
      "env": {},
      "timeout": 900000
    }
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__ssh__(exec|get|put|sync_get|sync_put)",
        "hooks": [
          { "type": "command", "command": "<path>/ssh-mcp hook" }
        ]
      }
    ]
  }
}
```

Manual Codex entries that this plugin replaces:

```toml
[mcp_servers.ssh]
command = "<path>/ssh-mcp"
args = ["serve"]
```

```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__ssh__(exec|get|put|sync_get|sync_put)",
        "hooks": [
          { "type": "command", "command": "<path>/ssh-mcp hook" }
        ]
      }
    ]
  }
}
```
