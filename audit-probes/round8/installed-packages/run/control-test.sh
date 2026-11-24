#!/bin/bash
set -uo pipefail
vol=${1:-demo}
cfg=/etc/maki/volumes/$vol.toml
sock=/run/maki-control/$vol/control.sock
getent passwd op >/dev/null || useradd -M -G maki-admin op
getent passwd nobody2 >/dev/null || useradd -M nobody2
echo "--- root: maki status <config>"; maki status "$cfg"; echo "exit=$?"
echo "--- op (maki-admin): maki status --socket"; runuser -u op -- maki status --socket "$sock"; echo "exit=$?"
echo "--- op (maki-admin): maki status <config> (config is root:maki 0640)"; runuser -u op -- maki status "$cfg"; echo "exit=$?"
echo "--- nobody2 (no group): maki status --socket"; runuser -u nobody2 -- maki status --socket "$sock"; echo "exit=$?"
echo "--- nobody2: nbdinfo on the NBD socket"; runuser -u nobody2 -- nbdinfo "nbd+unix:///?socket=/run/maki/$vol/nbd.sock" 2>&1 | head -3; echo "exit=${PIPESTATUS[0]}"
echo "--- op (maki-admin, not maki): nbdinfo on the NBD socket"; runuser -u op -- nbdinfo "nbd+unix:///?socket=/run/maki/$vol/nbd.sock" 2>&1 | head -3; echo "exit=${PIPESTATUS[0]}"
echo "--- op: maki metrics --socket | head"; runuser -u op -- maki metrics --socket "$sock" | head -15; echo "exit=${PIPESTATUS[0]}"
echo "--- op: maki checkpoint --socket"; runuser -u op -- maki checkpoint --socket "$sock"; echo "exit=$?"
echo "--- root: maki check <config> while the daemon runs"; maki check "$cfg"; echo "exit=$?"
echo "--- root: maki check --deep while the daemon runs (must refuse: lock held)"; maki check "$cfg" --deep; echo "exit=$?"
echo "--- root: maki attach (prints the privileged command, exit 3)"; maki attach "$cfg"; echo "exit=$?"
