#!/bin/bash
# Unmount and delete the work dir: teardown.sh <work-dir>
set -euo pipefail
work=$(realpath "$1"); root=$work/root
for m in "$root/dev" "$root/sys" "$root/proc"; do
  if mountpoint -q "$m"; then mount --make-rslave "$m" 2>/dev/null || true; umount -R "$m" || umount -l "$m"; fi
done
if findmnt -rn -o TARGET | grep -q "^$work/"; then echo "still mounted below $work" >&2; exit 1; fi
rm -rf --one-file-system "$work"
