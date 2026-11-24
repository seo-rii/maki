#!/bin/bash
# Run a command inside the booted container of a root: in.sh <deb12|el9> cmd...
set -euo pipefail
name=$1; shift
pid=
for p in /proc/[0-9]*; do
  if [ "$(cat "$p/comm" 2>/dev/null)" = systemd ] && [ "$(readlink "$p/root" 2>/dev/null)" = "/home/user/tgt/audit8-pkg/$name" ] && [ "$(awk '/^NSpid:/ {print $NF}' "$p/status")" = 1 ]; then pid=${p#/proc/}; fi
done
[ -n "$pid" ] || { echo "no booted systemd for $name" >&2; exit 1; }
exec nsenter -t "$pid" -m -p -u -i -n -C -r -w /usr/bin/env -i HOME=/root TERM=dumb LANG=C.UTF-8 \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SYSTEMD_PAGER= SYSTEMD_COLORS=0 "$@"
