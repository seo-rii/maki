#!/bin/bash
# Boot the root's own systemd as PID 1 of private PID/mount/UTS/IPC/net/cgroup
# namespaces (a hand-made container; no systemd-nspawn on this host).
# Usage: boot.sh <deb12|el9>   -- runs in the foreground until the container's init exits.
# Host safety: /proc/sys and /sys are read-only inside, the network namespace is
# private, /dev is a private tmpfs with the standard pseudo devices only.
set -euo pipefail
name=$1
ROOT=/home/user/tgt/audit8-pkg/$name
STATE=/home/user/tgt/audit8-pkg/boot-$name
mkdir -p "$STATE"
exec unshare --mount --pid --uts --ipc --net --cgroup --fork --kill-child \
  /bin/bash -euc '
ROOT=$1; STATE=$2; name=$3
mount --make-rprivate /
mount --bind "$ROOT" "$ROOT"
mount -t proc proc "$ROOT/proc"
mount -o remount,bind,ro "$ROOT/proc/sys" 2>/dev/null || { mount --bind "$ROOT/proc/sys" "$ROOT/proc/sys"; mount -o remount,bind,ro "$ROOT/proc/sys"; }
mount -t sysfs -o ro sysfs "$ROOT/sys"
mount -t tmpfs -o mode=755 tmpfs "$ROOT/sys/fs/cgroup" 2>/dev/null || true
mount -t cgroup2 cgroup2 "$ROOT/sys/fs/cgroup"
mount -t tmpfs -o mode=755,nosuid tmpfs "$ROOT/dev"
for n in "null c 1 3 666" "zero c 1 5 666" "full c 1 7 666" "random c 1 8 666" "urandom c 1 9 666" "tty c 5 0 666"; do
  set -- $n; mknod -m "$5" "$ROOT/dev/$1" "$2" "$3" "$4"
done
mkdir -p "$ROOT/dev/pts" "$ROOT/dev/shm" "$ROOT/dev/mqueue"
mount -t devpts -o newinstance,ptmxmode=0666,mode=620,gid=5 devpts "$ROOT/dev/pts"
ln -s pts/ptmx "$ROOT/dev/ptmx"
ln -s /proc/self/fd "$ROOT/dev/fd"; ln -s /proc/self/fd/0 "$ROOT/dev/stdin"; ln -s /proc/self/fd/1 "$ROOT/dev/stdout"; ln -s /proc/self/fd/2 "$ROOT/dev/stderr"
mount -t tmpfs -o mode=1777 tmpfs "$ROOT/dev/shm"
: > "$ROOT/dev/console"; mount --bind "$STATE/console.log" "$ROOT/dev/console" 2>/dev/null || true
mount -t tmpfs -o mode=755,nosuid,nodev tmpfs "$ROOT/run"
mount -t tmpfs -o mode=1777 tmpfs "$ROOT/tmp"
# As on a booted host (and under nspawn), mounts below / propagate between the
# manager and the namespaces it forks; systemd relies on that for LoadCredential=.
# The peer group is new, so nothing propagates to the host.
mount --make-rshared "$ROOT"
hostname "audit8-$name"
ip link set lo up 2>/dev/null || true
echo $$ > "$STATE/init.pid.inner"
init=/lib/systemd/systemd; [ -x "$ROOT$init" ] || init=/usr/lib/systemd/systemd
exec chroot "$ROOT" /usr/bin/env -i container=audit8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  "$init" --system --log-target=console --log-level=info --show-status=no --default-standard-output=journal
' boot "$ROOT" "$STATE" "$name"
