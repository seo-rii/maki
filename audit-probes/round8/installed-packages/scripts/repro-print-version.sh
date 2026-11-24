#!/bin/bash
# Reproduce F-d: prepare_release.py --print-version inside the published source
# tree, extracted below another Git repository. Usage: repro-print-version.sh (uses a temp dir)
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
mkdir "$t/alone" && tar --no-same-owner -xzf "$here/dl/maki-0.1.0-rc.1-source.tar.gz" -C "$t/alone"
echo "### standalone"; (cd "$t/alone/maki-0.1.0" && GIT_CEILING_DIRECTORIES="$t" python3 -B scripts/prepare_release.py --print-version) || echo "exit=$?"
mkdir "$t/outer" && cd "$t/outer" && git init -q -b main .
printf '[workspace]\nmembers = []\n[workspace.package]\nversion = "7.7.7"\n' > Cargo.toml
git add Cargo.toml && git -c user.name=a -c user.email=a@example.invalid commit -q -m outer
mkdir third_party && tar --no-same-owner -xzf "$here/dl/maki-0.1.0-rc.1-source.tar.gz" -C third_party
echo "### below another repository whose HEAD is $(git rev-parse HEAD)"
(cd third_party/maki-0.1.0 && python3 -B scripts/prepare_release.py --print-version); echo "exit=$?"
