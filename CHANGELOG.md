# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] - 2026-06-06

### Added

- Add the `ssh-mcp import` CLI subcommand for bootstrapping `ssh-mcp.toml` from `~/.ssh/config`.

### Removed

- Remove `examples/import-ssh-config.rs` (replaced by the built-in subcommand).

## [0.2.4] - 2026-06-06

### Added

- Add bundled Claude Code and Codex plugin manifests for installing `ssh-mcp` as a plugin.
- Add a shared plugin MCP server definition and `PreToolUse` policy hook wrapper for host-affecting SSH tools.
- Add plugin settings defaults that protect `~/.ssh/ssh-mcp.toml`, `~/.ssh/ssh-mcp.ephem.toml`, and `~/.ssh/ssh-mcp/**` from agent edits.

## [0.2.3] - 2026-06-06

### Added

- Add a daemon-owned ephemeral inventory file (`ssh-mcp.ephem.toml`) for proposed hosts.
- Keep the main `ssh-mcp.toml` as read-only daemon input while `propose_host` and expired-host GC write only the ephemeral file.
- Reject duplicate host aliases across the main and ephemeral inventories through TOML-level parsing.

## [0.2.2] - 2026-06-06

### Fixed

- Propagate `sync_get` local mirror deletion failures instead of reporting a successful sync when stale local files remain.
- Surface expired-host TOML garbage-collection write-back failures as daemon warnings while keeping in-memory expiry behavior intact.
- Update the `ExecResult.note` schema documentation to cover both inline output-cap notes and trailing line-scoping pipe notes.

## [0.2.1] - 2026-06-04

### Changed

- Cap inline `exec` responses at 64 KiB so large command output stays readable and can be retrieved through `trace`.

## [0.2.0] - 2026-05-27

### Added

- Add the `propose_host` tool for appending reviewable, disabled ephemeral host entries.
- Add inline `host_key` pinning for proposed hosts.
- Add the `list_agent_keys` tool so callers can inspect public SSH agent identities.

### Changed

- Require `host_key` when proposing a host.
- Document the new host-key and agent-key workflows.

### Fixed

- Tighten ignored secret and credential file patterns.

## [0.1.0] - 2026-05-24

### Added

- Initial release of the policy-gated SSH MCP server for Claude Code.
- Add `serve` and `hook` subcommands, the daemon/control socket split, and offline policy evaluation.
- Add reusable SSH connection handling over `russh`, bounded connection setup, and persistent exec connections.
- Add MCP tools for `list_hosts`, `exec`, `trace`, `get`, `put`, `sync_get`, and `sync_put`.
- Add tar/gzip file transfer with additive excludes, destination resolution, trace inspection, and per-entry sync gating.
- Add POSIX and Windows remote transfer support, including Windows console-output decoding.
- Add SSH config import, per-host ports, reusable `def` rulesets, and policy checks for commands and paths.
- Add setup documentation, LaunchAgent template, Linux notes, public design documentation, end-to-end tests, and supply-chain audit configuration.
- Add LICENSE files, CONTRIBUTING.md, README badges, CI action pin-audit metadata, and audit-log file mode hardening.

[0.2.5]: https://github.com/naoto256/ssh-mcp/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/naoto256/ssh-mcp/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/naoto256/ssh-mcp/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/naoto256/ssh-mcp/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/naoto256/ssh-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/naoto256/ssh-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/naoto256/ssh-mcp/releases/tag/v0.1.0
