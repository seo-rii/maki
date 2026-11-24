#!/bin/bash
# Stop the nbdkit of this root's volume the way systemd stops the unit: SIGTERM to the main PID.
set -uo pipefail
vol=${1:-demo}
found=
for p in /proc/[0-9]*; do
  if [ "$(readlink "$p/root" 2>/dev/null)" = "$(readlink /proc/self/root)" ] && tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q "nbdkit .*config=/etc/maki/volumes/$vol.toml"; then
    pid=${p#/proc/}; found=$pid
    echo "SIGTERM -> $pid"; kill -TERM "$pid"
    for i in $(seq 600); do [ -d "/proc/$pid" ] || break; sleep 0.1; done
    if [ -d "/proc/$pid" ]; then echo "still running after 60s"; else echo "exited after ~$((i/10))s"; fi
  fi
done
[ -n "$found" ] || echo "no daemon found"
# systemd removes RuntimeDirectory= and the credentials when the unit stops.
rm -rf "/run/maki/$vol" "/run/maki-control/$vol" "/run/credentials/maki@$vol.service"
