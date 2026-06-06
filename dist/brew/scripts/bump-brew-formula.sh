#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: bump-brew-formula.sh vX.Y.Z [tap-repo-dir]

Updates Formula/ssh-mcp.rb in the Homebrew tap repo with release asset sha256
values, commits the change, and opens a pull request with gh.

Set SSH_MCP_BREW_DRY_RUN=1 to update files without committing or opening a PR.
EOF
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  usage
  exit 2
fi

tag="$1"
case "${tag}" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "release tag must look like vX.Y.Z: ${tag}" >&2
    exit 2
    ;;
esac

version="${tag#v}"
base_url="https://github.com/naoto256/ssh-mcp/releases/download/${tag}"
tap_repo="naoto256/homebrew-ssh-mcp"
branch="bump/ssh-mcp-${version}"
dry_run="${SSH_MCP_BREW_DRY_RUN:-0}"

assets=(
  "aarch64-apple-darwin"
  "x86_64-apple-darwin"
  "x86_64-unknown-linux-gnu"
)

if [ "$#" -eq 2 ]; then
  tap_dir="$2"
else
  tap_dir="$(mktemp -d)"
  git clone "https://github.com/${tap_repo}.git" "${tap_dir}"
fi

formula="${tap_dir}/Formula/ssh-mcp.rb"
if [ ! -f "${formula}" ]; then
  echo "missing tap formula: ${formula}" >&2
  echo "create Formula/ssh-mcp.rb in ${tap_repo} from dist/brew/README.md first" >&2
  exit 1
fi

cd "${tap_dir}"
git switch -c "${branch}"

FORMULA="${formula}" VERSION="${version}" ruby <<'RUBY'
formula = ENV.fetch("FORMULA")
version = ENV.fetch("VERSION")
text = File.read(formula)
pattern = /version "[^"]+"/
abort "version field not found" unless text.match?(pattern)
updated = text.sub(pattern, "version \"#{version}\"")
File.write(formula, updated)
RUBY

for target in "${assets[@]}"; do
  asset="ssh-mcp-v${version}-${target}.tar.gz"
  url="${base_url}/${asset}"
  sha="$(curl -fsSL "${url}" | shasum -a 256 | awk '{print $1}')"

  FORMULA="${formula}" TARGET="${target}" SHA="${sha}" ruby <<'RUBY'
formula = ENV.fetch("FORMULA")
target = ENV.fetch("TARGET")
sha = ENV.fetch("SHA")
text = File.read(formula)
pattern = /(ssh-mcp-v#\{version\}-#{Regexp.escape(target)}\.tar\.gz"\n\s+)(?:# Fill after release\.\n\s+)?sha256 "[0-9a-f]{64}"/
updated = text.sub(pattern, "\\1sha256 \"#{sha}\"")
abort "target not found or sha256 placeholder missing: #{target}" if updated == text
File.write(formula, updated)
RUBY
done

if [ "${dry_run}" = "1" ]; then
  git diff -- Formula/ssh-mcp.rb
  exit 0
fi

git add Formula/ssh-mcp.rb
git commit -m "Update ssh-mcp ${tag} checksums"
git push -u origin "${branch}"
gh pr create \
  --repo "${tap_repo}" \
  --base main \
  --head "${branch}" \
  --title "Update ssh-mcp ${tag} checksums" \
  --body "Updates Homebrew formula sha256 values for ${tag} release assets."
