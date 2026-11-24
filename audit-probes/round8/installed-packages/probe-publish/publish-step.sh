set -euo pipefail
state() {
  gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate > dist/releases.json
  gh api "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$TAG" > dist/refs.json
  python3 -B scripts/release_assets.py state --tag "$TAG" --releases dist/releases.json --refs dist/refs.json
}
before="$(state)"
if [ "$before" != "$(printf 'release=none\ntag=none')" ]; then
  echo "refusing to publish $TAG:" $before >&2
  exit 1
fi
touch dist/draft-requested
gh release create "$TAG" --draft --prerelease --latest=false --target "$GITHUB_SHA" \
  --title "Maki $TAG" --notes-file dist/notes.md dist/release/*
gh release view "$TAG" --json assets > dist/uploaded.json
python3 -B scripts/release_assets.py uploaded --view dist/uploaded.json --assets dist/release
gh release edit "$TAG" --draft=false
after="$(state)"
if [ "$after" != "$(printf 'release=prerelease\ntag=%s' "$GITHUB_SHA")" ]; then
  echo "after publishing $TAG:" $after "(expected a pre-release and the tag at $GITHUB_SHA)" >&2
  exit 1
fi
