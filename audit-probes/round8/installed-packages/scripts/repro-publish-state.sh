#!/bin/bash
# Reproduce F-f: the publish step of .github/workflows/release.yml (extracted verbatim into
# probe-publish/publish-step.sh) against probe-publish/bin/gh, a stand-in where GitHub already
# holds a published pre-release and the tag; FAKE_GH_API_FAILURES transport failures first.
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd); P=$here/probe-publish
for failures in 0 2; do
  echo "=== the first $failures gh api calls fail at the transport level"
  rm -f "$P/gh.log" "$P/gh.log.count" "$P/work/dist/draft-requested" "$P/work/dist/releases.json" "$P/work/dist/refs.json"
  (cd "$P/work" && env PATH="$P/bin:$PATH" TAG=v0.1.0-rc.1 GH_TOKEN=token GITHUB_REPOSITORY=seo-rii/maki \
     GITHUB_SHA=956e35461f1f40244ddb1ef480d9413f661c4270 FAKE_GH_LOG="$P/gh.log" FAKE_GH_API_FAILURES=$failures \
     bash --noprofile --norc -eo pipefail "$P/publish-step.sh"); echo "step exit=$?"
  echo "gh calls:"; cat "$P/gh.log"; ls "$P/work/dist/draft-requested" 2>&1
done
