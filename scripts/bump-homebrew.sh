#!/usr/bin/env bash
# Update Formula/contour*.rb to the newest macadmins/contour release (prereleases included).
# Prints the new version, or nothing when already current.
set -euo pipefail
cd "$(dirname "$0")/.."

repo=macadmins/contour
tag=$(gh api "repos/$repo/releases?per_page=1" --jq '.[0].tag_name')
ver=${tag#v}
current=$(sed -n 's/^  version "\(.*\)"/\1/p' Formula/contour.rb)
[ "$ver" = "$current" ] && exit 0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gh release download "$tag" -R "$repo" -D "$tmp" -p 'checksums-*.txt'
sums=$(cat "$tmp"/checksums-*.txt)

sha() { grep -F " $1" <<<"$sums" | awk '{print $1}' | head -n1; }

for formula in contour contour-mcp; do
  f=Formula/$formula.rb
  sed -i.bak "s/^  version \".*\"/  version \"$ver\"/" "$f"
  for target in macos-arm64.zip aarch64-unknown-linux-gnu.tar.gz x86_64-unknown-linux-gnu.tar.gz; do
    asset="$formula-$ver-$target"
    new=$(sha "$asset")
    [ -n "$new" ] || { echo "no checksum for $asset" >&2; exit 1; }
    # Rewrite the URL and the sha256 line that follows it.
    sed -i.bak -E "/${target//./\\.}\"\$/{n;s/sha256 \".*\"/sha256 \"$new\"/;}" "$f"
    sed -i.bak -E "s#download/v[^/]+/$formula-[^\"]*$target#download/$tag/$asset#" "$f"
  done
  rm -f "$f.bak"
done
echo "$ver"
