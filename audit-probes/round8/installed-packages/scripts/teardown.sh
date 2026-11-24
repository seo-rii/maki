#!/bin/bash
# Unmount everything below the audit8 package roots, verify, then delete them.
set -euo pipefail
base=/home/user/tgt/audit8-pkg
for root in "$base/deb12" "$base/el9"; do
  [ -d "$root" ] || continue
  for slave in "$root/sys" "$root/dev"; do
    if mountpoint -q "$slave"; then mount --make-rslave "$slave"; fi
  done
  while read -r target; do
    mountpoint -q "$target" || continue
    umount -R "$target" 2>/dev/null || umount -l "$target"
  done < <(findmnt -rn -o TARGET | grep -E "^$root(/|$)" | sort -r)
  if findmnt -rn -o TARGET | grep -qE "^$root(/|$)"; then
    echo "still mounted below $root" >&2; exit 1
  fi
  if [ "${1:-}" = "--delete" ]; then rm -rf --one-file-system "$root"; fi
done
