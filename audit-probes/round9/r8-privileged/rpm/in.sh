#!/bin/bash
# Run a command inside the root: in.sh <work-dir> cmd...   (mounts proc/sys/dev on first use)
set -euo pipefail
root=$(realpath "$1")/root; shift
mountpoint -q "$root/proc" || mount -t proc proc "$root/proc"
mountpoint -q "$root/sys" || { mount --rbind /sys "$root/sys"; mount --make-rslave "$root/sys"; }
mountpoint -q "$root/dev" || { mount --rbind /dev "$root/dev"; mount --make-rslave "$root/dev"; }
exec chroot "$root" /usr/bin/env -i HOME=/root LANG=C.UTF-8 TERM=dumb PATH=/usr/sbin:/usr/bin "$@"
