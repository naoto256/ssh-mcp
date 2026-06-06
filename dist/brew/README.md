# HekateSSH Homebrew tap setup

The Homebrew tap repository `naoto256/homebrew-hekatessh` is the source of truth
for the actual formula. This directory only keeps the setup notes and the
post-release checksum bump scaffold for that tap.

Do not keep a live `Formula/hekatessh.rb` in this repository.

## Initial tap formula

After publishing `v0.4.0`, create `Formula/hekatessh.rb` in
`naoto256/homebrew-hekatessh`. The formula should:

- install the matching release asset for each supported target:
  `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`
- set `version "0.4.0"`
- install the `hekatessh` binary into `bin`
- define a `service do` block that runs `hekatessh daemon`
- include caveats for first setup:
  `hekatessh import > ~/.ssh/hekatessh.toml`, then
  `brew services start hekatessh`
- include the Claude Code and Codex plugin registration commands below

The initial tap formula may use temporary zeroed `sha256` values while the
release assets are being wired, but the tap PR should replace them before
merge.

Template for the initial tap formula:

```ruby
class HekateSsh < Formula
  desc "Policy-gated SSH execution MCP server for Claude Code and Codex"
  homepage "https://github.com/naoto256/hekatessh"
  version "0.4.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/naoto256/hekatessh/releases/download/v#{version}/hekatessh-v#{version}-aarch64-apple-darwin.tar.gz"
      # Fill after release.
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/naoto256/hekatessh/releases/download/v#{version}/hekatessh-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      # Fill after release.
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "hekatessh"
  end

  service do
    run [opt_bin/"hekatessh", "daemon"]
    keep_alive true
    log_path var/"log/hekatessh.log"
    error_log_path var/"log/hekatessh.log"
  end

  def caveats
    <<~EOS
      First setup:
        hekatessh import > ~/.ssh/hekatessh.toml
        brew services start hekatessh

      Claude Code plugin registration:
        /plugin marketplace add naoto256/hekatessh
        /plugin install hekatessh@naoto256-hekatessh

      Codex plugin registration:
        codex plugin marketplace add naoto256/hekatessh
        codex plugin add hekatessh@naoto256-hekatessh

      Restart Claude Code or Codex after installing the plugin.
    EOS
  end

  test do
    assert_match "hekatessh", shell_output("#{bin}/hekatessh --help")
  end
end
```

## Post-release checksum flow

After creating the tap formula and publishing `v0.4.0` release assets:

```sh
dist/brew/scripts/bump-brew-formula.sh v0.4.0 /path/to/homebrew-hekatessh
```

The script downloads the release assets, updates `Formula/hekatessh.rb` in the
tap repo, commits the checksum change, and opens a tap PR with `gh`. It uses the
user's existing GitHub CLI authentication and does not require or store a token.

For a no-commit preview:

```sh
HEKATESSH_BREW_DRY_RUN=1 dist/brew/scripts/bump-brew-formula.sh v0.4.0 /path/to/homebrew-hekatessh
```

Expected release asset names:

- `hekatessh-v0.4.0-aarch64-apple-darwin.tar.gz`
- `hekatessh-v0.4.0-x86_64-unknown-linux-gnu.tar.gz`

## User install flow

```sh
brew tap naoto256/hekatessh
brew install hekatessh
hekatessh import > ~/.ssh/hekatessh.toml
brew services start hekatessh
```

Then register the plugin.

Claude Code:

```text
/plugin marketplace add naoto256/hekatessh
/plugin install hekatessh@naoto256-hekatessh
```

Codex:

```sh
codex plugin marketplace add naoto256/hekatessh
codex plugin add hekatessh@naoto256-hekatessh
```

Restart Claude Code or Codex after installing the plugin.
