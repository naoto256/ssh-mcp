# ssh-mcp — design

This document explains **why** ssh-mcp is shaped the way it is. The
[README](README.md) covers the **what** and **how to set it up**.

The core claim: SSH execution is poorly served by the file-grained Claude
Code permission model, and the gap is fixable by moving SSH off the `Bash`
tool onto a structured MCP server with policy enforcement living outside
the model.

## 1. Why a separate server

Claude Code's permission model is built around tool-name and argument-shape
rules. For `Bash(...)` that works: a deny rule against `Bash(rm -rf *)`
matches every command starting with that prefix.

It does **not** work for SSH. The rule grammar matches on the tool name
plus argument prefixes; it cannot match on the *target host*. Every SSH
target therefore falls into the same bucket: either you allow `Bash(ssh *)`
wholesale and lose all control, or you keep it on the ask list and answer
the prompt every single time, including for the lab box you are happy to
let the agent use freely.

There is a `PreToolUse` hook escape hatch — and projects like the user's
own `ask-permission.py` lean on it — but the hook still has to scrape the
command string to learn which host the agent is targeting, and the result
is fragile.

ssh-mcp solves the per-host problem by *being a different tool*. The MCP
server presents structured arguments (`host`, `command`, `op`); the hook
reads the `host` field directly; the inventory says what each host's
policy is.

## 2. Enforcement outside the model

The arrangement keeps **enforcement out of the model**. The model only
proposes a host and a command (or a transfer); whether it runs is decided
by non-model code:

```
Claude (model)
  │  proposes mcp__ssh__exec{host, command, op}
  ▼
Claude Code harness ─spawn→ ssh-mcp serve (shim) ─UDS: mcp.sock─→ ┐
  │                          stdio↔UDS byte relay only             │
  │                                                                ▼
  ├─spawn→ ssh-mcp hook ───── UDS: control.sock ────────→ ssh-mcp daemon
  │           policy proxy                              owns inventory,
  │                                                     evaluates policy,
  │  decision ← hook ← daemon                           runs SSH, audits
  │  Allow → tool call passes through                          │
  │  Ask   → user is prompted                                  │
  │  Deny  → tool call blocked                                 ▼
                                                       remote host (russh)
```

One binary, three subcommands:

| Subcommand | Role |
|---|---|
| `ssh-mcp daemon` | Resident server, shared by every Claude Code session. Owns the host inventory, the SSH connection pool, policy evaluation, and the audit log. |
| `ssh-mcp serve`  | Per-session MCP server the harness spawns. A thin shim that relays bytes between the harness's stdio and the daemon's `mcp.sock`; speaks no MCP itself. |
| `ssh-mcp hook`   | A `PreToolUse` hook program, a pure proxy. Forwards the policy query to the daemon's `control.sock` and returns its decision. Holds no policy logic. |

The two UDS sockets live under `~/.ssh/ssh-mcp/`. They are owner-only, the
daemon checks each connection's peer uid, and there is no TCP port. The
attack surface is "an attacker with my own uid on my own machine", which
is the trust boundary the operating system gives you anyway.

The shim model exists because Claude Code can only spawn an MCP server
over stdio or HTTP, neither of which lets multiple sessions share state
(in particular the SSH connection pool, which has to be cross-session for
the connection reuse to pay off). The shim is the bridge.

## 3. The policy gate

### 3.1 Gates composed strictest-wins

A host's `policy` is a **set** of gates. The decision is "the strictest
result wins", precedence `deny > ask > allow`. The gates available are:

| Gate | Decision source |
|---|---|
| `free` | Constant allow. Equivalent to an empty gate set. |
| `def`  | Rules written inline under `[hosts.<alias>.def]` in the inventory. |
| `claude` | The `permissions.*` rules from `~/.claude/settings.json`. |
| `{ hook = "..." }` | An external hook program, same protocol as Claude Code's `PreToolUse` hook. |

Mixing matters. A host that needs to consult both an external program and
the user's own settings can do so by listing both gates; the stricter wins.
A host that should never trigger an ask should be declared `free` —
explicitly, so the intent is in the inventory.

### 3.2 Why the user's `~/.claude/settings.json` is honored

The `claude` gate exists so that rules the user has already written for
their local environment can be carried into SSH execution without being
duplicated. A user who has `deny = ["Bash(rm -rf *)"]` locally probably
wants it to apply on the build server too.

Only the user-level (`~/.claude/settings.json`) is read — not project,
local, or managed. Project and local scopes are about protecting *this
working tree*; that has no meaning on a remote host. Managed scope is
about protecting *this machine*, again local-only. User scope is about
the user's general agent-behavior preferences, which port cleanly.

### 3.3 Per-entry policy for sync transfers

A single command call is one judgment subject: the gate asks "may
`Bash(systemctl restart nginx)` run?" and answers once. A file transfer
that touches one path is the same shape.

A `sync_*` call is different. It touches many files, each independently;
a coarse-grained "may the tree be touched?" question loses too much. A
deny rule on one file inside the tree silently has no effect; an ask
rule cannot point at the files driving the prompt.

So `sync_*` is gated **per entry**. The hook walks both sides with
`find -print0` (paths only, no hashing — see §4.3), classifies every
path that would be touched into create / update / delete, and evaluates
`Edit(remote_abs)` against the host policy and `Edit(local_abs)` against
the user settings for each one. The single Decision the hook returns is
strictest-wins across every entry: one Deny ruins the transfer, one Ask
covers the whole change set in one prompt.

`get` and `put` keep their path-level gate: the cp-merge rule
means they target one location, and the coarse question already captures
intent.

## 4. File transfer

### 4.1 cp-merge semantics on `get` / `put`

`get foo.txt /inbox/` and `get foo.txt /inbox/foo.txt` are
different in standard Unix:

- the first places `foo.txt` inside `/inbox/` (existing directory)
- the second replaces the file at `/inbox/foo.txt`

`cp` and `rsync` both follow this rule. Earlier versions of ssh-mcp did
not — they always replaced the target — and the failure mode was severe:
`get remote=/tmp/.claude local=~` would have replaced the home
directory wholesale with the downloaded entry.

The current rule is: if the destination is an existing directory, the
entry is placed inside it under the source's base name; otherwise, the
destination is replaced. Trailing slashes carry no meaning — an LLM is
likely to drop them — so the directory check, not the spelling, decides
the branch. To replace an existing directory wholesale, delete it first
on purpose.

The upload side adds one round-trip (`test -d`) before the transfer, to
ask the remote whether the destination is a directory. The download side
checks locally.

### 4.2 Mirror semantics on `sync_*`

`sync_get` and `sync_put` deliberately do **not** apply cp-merge. Both
paths are roots; the mapping is the same every run; files in the
destination that are absent from the source are deleted. This is
rsync's typical `src/ dst/` shape, and it is what "mirror" wants: a
stable, idempotent operation.

The remote root is created on demand by the upload side's `mkdir -p`.

### 4.3 Two-stage walk: paths in the hook, hashes in the transfer

Per-entry policy needs the *set of paths* that would be touched. It
does **not** need to know whether the file content has changed.
`Edit(path)` is the same question whether the bytes will change or
not — the gate treats "write a file with new contents" and "write the
same bytes again" identically.

So the hook walks both sides with `find -print0` and stops there.
The hash work happens only in the actual transfer (the MCP call), where
it pays for itself: a hash match means the file does not have to be sent.

This is the difference between an evaluation that runs in well under a
second on a 10 k file tree and one that would take noticeably longer.

### 4.4 Single bytes-on-the-wire format

All four transfer tools share one implementation: a gzip-compressed tar
archive streamed over the SSH exec channel. No external `rsync`, no
helper binary on the remote, no sub-process bridge. The remote runs
ordinary `tar -cz` (download) or `tar -xz` (upload); the local side
uses `tar-rs` + `flate2`.

`sync_*` packs only the files the change set marks as `Create` or
`Update`. Files matching by hash never cross the wire; files present
only on the destination are removed by a one-shot `rm -rf` of the
relative paths.

### 4.5 Result shape: counts in the tool, lines in the trace

The tool result for a transfer is the byte count (for `get` /
`put`) or per-op counts (for `sync_*`). It deliberately does **not**
contain the per-file list, even when only a handful of files moved.
Every line of tool output is context the model has to spend reading.

The full per-file list lives in the per-session trace buffer (§5), as
`<verb> <path>` lines that grep cleanly.

`bytes` is what crossed the wire — gzip-compressed tar payload
including framing and per-file metadata — not the sum of file content
sizes. A 4 KiB file uploads as ~4.2 KiB on the wire because of that
framing. For `sync_*` the count covers only the files that actually
moved (`created` + `updated`); a no-op run where every file matched
by sha-256 returns `bytes = 0`. The number is a transfer-cost
indicator, not a file-size measurement.

## 5. The trace tool

### 5.1 The op discipline

Models running shells reflexively pipe through `tail`, `head`, and
`grep` to keep terminal output manageable. The same instinct fits SSH
exec: most of the time the agent wants the last error line, the first
hit, or a count.

ssh-mcp lifts that into the tool surface: `exec` (and `trace`) require an
`op` parameter — exactly one of `tail`, `head`, or `grep`, with `grep`
combinable with `head` or `tail`. An empty op is rejected so an unscoped
dump cannot be requested by accident.

The tool returns only the scoped slice. The full stdout/stderr is kept
in the trace buffer (next).

A model that has internalised "scope your output" will still sometimes
double-scope — pass an `op` *and* pipe the command through `tail` in
the shell. The reflex is safe-feeling but expensive: the shell has
already scoped at its level, so the trace buffer only contains the
post-pipe slice. Re-scoping through `trace` would just return the
same lines back.

Spelling that out in the description is necessary but not sufficient
(models read schemas, then fall back to instinct). So the daemon also
notices: a quote-aware scan finds the last unquoted pipe and, if it
targets a known scoping program (`tail` / `head` / `grep` / `egrep` /
`fgrep` / `rg`), the result carries an advisory `note` explaining what
was lost and pointing at `op`. The exec still runs — the command was
the caller's intent — and the note is just a low-strength signal that
travels back with the result. The combination of "execution succeeds"
plus "small annoying message every time" turns out to be exactly the
shape that nudges a model away from the pattern without provoking it
into looking for a workaround.

### 5.2 The ring buffer

Each MCP session has its own ring buffer holding the last five tool
calls in full. A new tool — `trace(index, op, stream?)` — fetches one
of those entries by index (0 = most recent, up to 4) and applies an op
to the body before returning it. `trace` itself is not recorded.

The buffer is per-session because sessions are independent agent
conversations; one session must not be able to see another's traces.
Each entry has a 10 MiB body cap; anything larger is truncated and the
entry carries a `truncated` flag. Both the buffer and its caps live in
memory only.

The intent is to keep the *result* of each tool slim — exit code, byte
count, op-scoped lines — while making the unscoped detail reachable on
demand. The model is told to scope through `op` and re-scope through
`trace`, never by piping in the command itself, because doing so
discards the very bytes `trace` would have been useful for.

### 5.3 Channel tagging, interleaving, and grep on bare lines

A naive implementation stores trace lines as `"stdout: <text>"` /
`"stderr: <text>"` strings — one flat list with the channel folded
into the line text. It is also wrong in two subtle ways.

First, `grep` against `"stdout: <text>"` is not `grep` against
`<text>`. A pattern like `^[1-9]$` that matched on the original
`exec` result silently matches nothing on the trace — and the failure
mode is an empty result with no error, the worst possible UX for a
re-inspection tool.

Second, accumulating "all stdout, then all stderr" loses the temporal
interleaving. A build log where stderr warnings land between stdout
progress lines reads back as two disconnected blocks.

ssh-mcp's trace addresses both. Lines are stored with an explicit
channel tag — `Stdout`, `Stderr`, or `Transfer` — and the exec
collector preserves the raw arrival order of stdout and stderr
chunks. The trace handler splits those chunks into ordered,
channel-tagged lines (whichever channel produced a `\n` first wins
the next slot), so the natural reading order is preserved across
both streams. `grep` then matches against the bare text — never
against any prefix — so a pattern that worked on the original
`exec` result keeps working through `trace` unchanged.

The `stream` parameter (default `both`) chooses what `trace` surfaces
for an exec entry. `stdout` or `stderr` return only that channel,
unprefixed (same shape as the corresponding field on the original
`exec` result). `both` returns both channels in arrival order with
`stdout:` / `stderr:` prefixes so the caller can tell them apart.
Transfer entries ignore the selector — they have no channel concept.

### 5.4 Transfer entries

A transfer's trace body is line-oriented:

```
create src/foo.rs
update Cargo.toml
delete src/old.rs
skip   src/main.rs
```

Every line carries the `Transfer` channel tag, so the `stream`
selector passes them through unchanged. The `skip` lines
(hash-matched, no-op entries) are held in a separate companion list
because they typically dwarf the actionable entries; `trace(...
include_skipped=true)` mixes them into the body before the op is
applied.

## 6. Connection model

russh, the Rust SSH client, exposes connections and channels as separate
objects. One authenticated connection can carry many channels; each
`exec` runs on its own short-lived channel. ssh-mcp reuses this directly:

- One russh `Handle` per host, kept in an in-process pool, shared across
  every MCP session.
- Per-`exec` channel — opened, used for one command, closed.
- Per-transfer channel — opened, used for one tar stream or one walk
  command, closed.

This is the same multiplexing OpenSSH offers via `ControlMaster`, with
the advantage that it is in-process and needs no external socket.

Each `exec` is stateless. cwd and shell state do not carry across calls,
because the local Bash tool's cwd persistence is anchored in the
project working tree and a remote host has no equivalent anchor — making
remote `exec` stateless matches the "outside the working tree" behavior
of the local tool, and the simplicity is its own reward.

Authentication is via the SSH agent (no key material crosses ssh-mcp's
process boundary). Host keys are checked strictly against
`~/.ssh/known_hosts`.

`proxy_jump` works by tunneling: open a `direct-tcpip` channel to the
next hop, wrap it as a stream, and feed it to russh's `connect_stream`.
Each hop is authenticated independently, so no agent forwarding is
needed (and the keys never leave the local machine).

## 7. Fail-closed

Every abnormal path returns `deny`:

| Failure | Behavior |
|---|---|
| Hook cannot reach the daemon (e.g. daemon stopped) | `deny`, with a message in the prompt. |
| Daemon control-socket peer is not the daemon's uid | Connection rejected at accept. |
| Hook encounters an unhandled exception | Caught; emits `deny` JSON and exits 0. |
| Inventory file is malformed | `deny`. |
| Host not in inventory | `deny`. |
| Remote walk command fails | `deny`. |
| Remote path will not normalize (e.g. tries `..` past the root) | `deny`. |

Normal "no matching rule" — every gate returned `Unset` — is *not* an
error. It defers to the request's `permission_mode`: `bypassPermissions`
allows, anything else asks. This matches Claude Code's behavior with no
matching local rule. A deny only happens when a deny rule actually
matched.

## 8. The trust root

The whole arrangement rests on a small set of files. If the agent can
edit them, the policy is fiction:

- `~/.ssh/ssh-mcp.toml` — the inventory and per-host policy.
- `~/.claude/settings.json` — user-level Claude Code permissions and the
  hook wiring.
- `~/.claude.json` — the MCP server registration.
- The `ssh-mcp` binary itself.

These should be on the `permissions.ask` (or `deny`) list. Setup
instructions in the README spell out the exact rules.

There is still a residual exposure: a sufficiently general `Bash(...)`
allow could in principle let the agent write to these files through the
shell. Closing that hole completely would require a sandbox layer.
ssh-mcp does not claim to be that.

## 9. What's deliberately out of scope

A few decisions are explicit non-features:

- **Remote `managed-settings.json` is not consulted.** The remote host's
  organization policy is its own to enforce; ssh-mcp does not try to
  read it across the SSH connection. The added complexity (remote-OS
  path variation, caching, unavailability handling) is not worth it
  while the user's own gates and the remote's own access controls
  already overlap.
- **No streaming output.** `exec` returns the buffered exit-code result.
  Long-running detached jobs are run with `nohup ... &` and polled,
  per the exec tool description.
- **No remote agent.** The remote side runs only commands that come with
  the OS (`find`, `tar`, `sha256sum` or `shasum`, `rm`). Distributing a
  helper would buy delta-block transfer or richer probes but break the
  property that any reasonable Unix host works out of the box.
- **No detached-job dedicated tool.** The polling idiom in the exec tool
  description is enough for now.

## 10. Rejected alternatives, briefly

A handful of paths were tried or considered and dropped:

- **Per-host SSH policy through `permissions.*` rules.** Cannot express
  host as a matcher; the rule grammar matches tool-and-arguments only.
- **HTTP daemon with a bearer token.** Even on loopback, a token is a
  thing that can leak; filesystem permissions plus peer-uid checks on a
  UDS socket give the same guarantee for free.
- **Stdio MCP server with no daemon.** Loses connection pool sharing
  across sessions, and the per-session sockets would collide.
- **Persistent shells.** Adds sentinel framing, forced serialization,
  reconnect-state-loss, and stdout/stderr merging — none of which the
  local Bash tool has. Stateless `exec` is the symmetric choice.
- **rsync transport.** Tried; the bridge between local `rsync` and the
  russh channel had stdin-relay deadlocks and version-incompatibility
  problems, and the direction itself (bridging an external binary)
  was the wrong shape. The change-set engine replaces rsync's delta in
  the file-granularity case, which covers the working-tree-to-build-rig
  use case the project actually has.
- **GPL-licensed rsync-protocol Rust crates** (`oc-rsync`). Linking would
  pull the copyleft into a MIT/Apache project.
- **Persistent agent on the remote host** (mutagen, sy-style). Adds a
  distribution and version-management burden that the project does not
  want to carry.

## 11. Audit trail

Every decision the daemon makes — exec, transfer, or hook query — is
appended to `~/.ssh/ssh-mcp/audit.jsonl` as a single JSON object per
line. Entries record the host alias, the subject (command or paths),
the permission mode, and the final decision. Secret-shaped environment
assignments in command strings are masked.

The audit log is append-only by convention and lives next to the
inventory. It is intended for after-the-fact review: which host did the
agent touch, when, under what decision.
