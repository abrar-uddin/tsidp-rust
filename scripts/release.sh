#!/usr/bin/env bash
# Cut a release: bump every version string, move the CHANGELOG "Unreleased"
# section under the new version, commit, tag, and (with --push) push the
# commit and tag. Pushing the tag triggers .github/workflows/release.yaml,
# which builds the binaries, the image (:X.Y.Z and :latest) and the chart, and
# publishes the GitHub Release.
#
#   scripts/release.sh 0.2.0           # prepare locally, review, then: git push && git push origin v0.2.0
#   scripts/release.sh 0.2.0 --push    # prepare and push
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:?version, e.g. 0.2.0 (no v prefix)}"
PUSH="${2:-}"
case "$VERSION" in *[!0-9.]*|"") echo "version must look like X.Y.Z" >&2; exit 2 ;; esac
TAG="v$VERSION"
git diff --quiet && git diff --cached --quiet || { echo "working tree not clean" >&2; exit 1; }
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && { echo "tag $TAG exists" >&2; exit 1; }
DATE=$(date -u +%Y-%m-%d)
OWNER_REPO=$(git remote get-url origin | sed -E 's#.*github.com[:/]##; s#\.git$##')

sed -i -E "0,/^version = \"[0-9.]+\"/s//version = \"$VERSION\"/" Cargo.toml
sed -i -E "s/^version: .*/version: $VERSION/; s/^appVersion: .*/appVersion: \"$VERSION\"/" charts/tsidp/Chart.yaml
sed -i -E "s#(ghcr.io/[^/]+/tsidp-rust):[0-9.]+#\1:$VERSION#" deploy/kubernetes/base/statefulset.yaml compose.yaml
# Cargo.lock carries the crate's own version; refresh it without touching deps.
if command -v cargo >/dev/null 2>&1; then cargo update -p tsidp --offline -q 2>/dev/null || cargo update -p tsidp -q
else ./scripts/dev.sh sh -c "cargo update -p tsidp --offline -q 2>/dev/null || cargo update -p tsidp -q"; fi

# CHANGELOG: rename Unreleased, add a fresh Unreleased, update link refs.
python3 - "$VERSION" "$DATE" "$OWNER_REPO" <<'EOF'
import re, sys
v, date, repo = sys.argv[1:4]
p = "CHANGELOG.md"; s = open(p, encoding="utf-8").read()
assert "## [Unreleased]" in s, "CHANGELOG.md has no Unreleased section"
s = s.replace("## [Unreleased]", f"## [Unreleased]\n\n## [{v}] - {date}", 1)
prev = re.search(r"^\[Unreleased\]: .*compare/v([0-9.]+)\.\.\.HEAD$", s, re.M)
prev_v = prev.group(1) if prev else None
s = re.sub(r"^\[Unreleased\]: .*$", f"[Unreleased]: https://github.com/{repo}/compare/v{v}...HEAD", s, flags=re.M)
link = (f"[{v}]: https://github.com/{repo}/compare/v{prev_v}...v{v}" if prev_v
        else f"[{v}]: https://github.com/{repo}/releases/tag/v{v}")
s = s.replace(f"[Unreleased]: https://github.com/{repo}/compare/v{v}...HEAD",
              f"[Unreleased]: https://github.com/{repo}/compare/v{v}...HEAD\n{link}", 1)
open(p, "w", encoding="utf-8", newline="\n").write(s)
EOF

git add -A
git commit -q -m "release $TAG"
git tag -a "$TAG" -m "tsidp-rust $TAG"
echo "prepared $TAG:"; git --no-pager show --stat --oneline HEAD | head -12
if [ "$PUSH" = "--push" ]; then
  git push origin HEAD && git push origin "$TAG"
  echo "pushed; watch https://github.com/$OWNER_REPO/actions"
else
  echo "review, then: git push origin HEAD && git push origin $TAG"
fi
