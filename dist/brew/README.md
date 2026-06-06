# ssh-mcp Homebrew tap setup

The Homebrew tap repository `naoto256/homebrew-ssh-mcp` is the source of truth
for the actual formula. This directory only keeps the setup notes and the
post-release checksum bump scaffold for that tap.

Do not keep a live `Formula/ssh-mcp.rb` in this repository.

## Initial tap formula

After publishing `v0.3.0`, create `Formula/ssh-mcp.rb` in
`naoto256/homebrew-ssh-mcp`. The formula should:

- install the matching release asset for each supported target:
  `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`
- set `version "0.3.0"`
- install the `ssh-mcp` binary into `bin`
- define a `service do` block that runs `ssh-mcp daemon`
- include caveats for first setup:
  `ssh-mcp import > ~/.ssh/ssh-mcp.toml`, then
  `brew services start ssh-mcp`
- include the Claude Code and Codex plugin registration commands below

The initial tap formula may use temporary zeroed `sha256` values while the
release assets are being wired, but the tap PR should replace them before
merge.

Template for the initial tap formula:

```ruby
class SshMcp < Formula
  desc "Policy-gated SSH execution MCP server for Claude Code and Codex"
  homepage "https://github.com/naoto256/ssh-mcp"
  version "0.3.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/naoto256/ssh-mcp/releases/download/v#{version}/ssh-mcp-v#{version}-aarch64-apple-darwin.tar.gz"
      # Fill after release.
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/naoto256/ssh-mcp/releases/download/v#{version}/ssh-mcp-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      # Fill after release.
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "ssh-mcp"
  end

  service do
    run [opt_bin/"ssh-mcp", "daemon"]
    keep_alive true
    log_path var/"log/ssh-mcp.log"
    error_log_path var/"log/ssh-mcp.log"
  end

  def caveats
    <<~EOS
      First setup:
        ssh-mcp import > ~/.ssh/ssh-mcp.toml
        brew services start ssh-mcp

      Claude Code plugin registration:
        /plugin marketplace add naoto256/ssh-mcp
        /plugin install ssh-mcp@naoto256-ssh-mcp

      Codex plugin registration:
        codex plugin marketplace add naoto256/ssh-mcp
        codex plugin add ssh-mcp@naoto256-ssh-mcp

      Restart Claude Code or Codex after installing the plugin.
    EOS
  end

  test do
    assert_match "ssh-mcp", shell_output("#{bin}/ssh-mcp --help")
  end
end
```

## Post-release checksum flow

After creating the tap formula and publishing `v0.3.0` release assets:

```sh
dist/brew/scripts/bump-brew-formula.sh v0.3.0 /path/to/homebrew-ssh-mcp
```

The script downloads the release assets, updates `Formula/ssh-mcp.rb` in the
tap repo, commits the checksum change, and opens a tap PR with `gh`. It uses the
user's existing GitHub CLI authentication and does not require or store a token.

For a no-commit preview:

```sh
SSH_MCP_BREW_DRY_RUN=1 dist/brew/scripts/bump-brew-formula.sh v0.3.0 /path/to/homebrew-ssh-mcp
```

Expected release asset names:

- `ssh-mcp-v0.3.0-aarch64-apple-darwin.tar.gz`
- `ssh-mcp-v0.3.0-x86_64-unknown-linux-gnu.tar.gz`

## User install flow

```sh
brew tap naoto256/ssh-mcp
brew install ssh-mcp
ssh-mcp import > ~/.ssh/ssh-mcp.toml
brew services start ssh-mcp
```

Then register the plugin.

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

Restart Claude Code or Codex after installing the plugin.
