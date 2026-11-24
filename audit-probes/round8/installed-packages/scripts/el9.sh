#!/bin/bash
# Run a command inside the CentOS Stream 9 root (sandbox plumbing: mounts, DNS, proxy CA).
set -euo pipefail
ROOT=/home/user/tgt/audit8-pkg/el9
mounted() { mountpoint -q "$1"; }
mounted "$ROOT/proc" || mount -t proc proc "$ROOT/proc"
mounted "$ROOT/sys" || { mount --rbind /sys "$ROOT/sys"; mount --make-rslave "$ROOT/sys"; }
mounted "$ROOT/dev" || { mount --rbind /dev "$ROOT/dev"; mount --make-rslave "$ROOT/dev"; }
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
mkdir -p "$ROOT/root/sandbox"; cp /root/.ccr/ca-bundle.crt "$ROOT/etc/sandbox-proxy-ca.pem"; chmod 644 "$ROOT/etc/sandbox-proxy-ca.pem"
cp /root/.ccr/ca-bundle.crt "$ROOT/etc/sandbox-proxy-ca.pem"
exec chroot "$ROOT" /usr/bin/env -i \
  HOME=/root TERM=dumb LANG=C.UTF-8 \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin \
  HTTPS_PROXY="${HTTPS_PROXY:-}" https_proxy="${https_proxy:-}" \
  NO_PROXY="${NO_PROXY:-}" no_proxy="${no_proxy:-}" \
  SSL_CERT_FILE=/etc/sandbox-proxy-ca.pem \
  "$@"
