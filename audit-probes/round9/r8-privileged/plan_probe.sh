#!/bin/bash
# Probe: maki-attach --plan and messages for a default configuration path in
# several states, as root and as an unprivileged user, in a private mount
# namespace with an empty /run and its own /etc/maki.
# Usage: unshare -m bash plan_probe.sh /path/to/maki-attach
B=$1
mount -t tmpfs -o mode=755 tmpfs /run || exit 9
# /etc/maki may not exist on the host: the directory is then made for the
# mount and removed again at the end (a mkdir is not private to the namespace).
made=; [ -d /etc/maki ] || { mkdir /etc/maki && made=1; }
mount -t tmpfs -o mode=755 tmpfs /etc/maki || exit 9
trap 'umount /etc/maki; [ -z "$made" ] || rmdir /etc/maki' EXIT
as_nobody() { setpriv --reuid 65534 --regid 65534 --clear-groups "$@"; }
show() { echo "--- $*"; "$@"; echo "[status $?]"; }
CFG='volume_uuid = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c"
vg_name = "vg_custom"
nbd_device = "/dev/nbd5"
mountpoint = "/srv/custom"
'
echo "=== 1. no /etc/maki/attach at all"
for v in attach detach cleanup recover verify; do show as_nobody $B $v --volume demo --plan; done
show as_nobody $B grow --volume demo --size-bytes 1024 --plan
echo "=== 2. /etc/maki/attach 0700 root, demo.toml 0600"
install -d -m 0700 /etc/maki/attach; printf '%s' "$CFG" > /etc/maki/attach/demo.toml; chmod 600 /etc/maki/attach/demo.toml
for v in attach detach cleanup recover verify recover-failed-start; do show as_nobody $B $v --volume demo --plan; done
show as_nobody $B grow --volume demo --size-bytes 1024 --plan
show $B attach --volume demo --plan
echo "=== 3. directory 0755, file 0600 (nobody may search, not read)"
chmod 755 /etc/maki/attach
for v in attach verify; do show as_nobody $B $v --volume demo --plan; done
echo "=== 4. executing verbs as nobody (no state dir in the empty /run)"
for v in attach detach cleanup recover verify; do show as_nobody $B $v --volume demo; done
show as_nobody $B grow --volume demo --size-bytes 1024
show as_nobody $B nbd-connect --nbd-device /dev/nbd9 --socket /run/x.sock --identifier maki-bootstrap-1
show as_nobody $B nbd-disconnect --nbd-device /dev/nbd9 --identifier maki-bootstrap-1
echo "=== 5. executing verbs as root, no state dir, config present"
for v in detach cleanup recover verify; do show $B $v --volume demo; done
show $B grow --volume demo --size-bytes 1024
echo "=== 6. dangling symlink at default path"
ln -s /etc/maki/attach/gone.toml /etc/maki/attach/dang.toml
for v in attach cleanup; do show $B $v --volume dang --plan; show $B $v --volume dang; done
show $B verify --volume dang --plan; show $B verify --volume dang
echo "=== 7. default path is a directory"
mkdir /etc/maki/attach/dir.toml
show $B attach --volume dir --plan; show $B cleanup --volume dir
echo "=== 8. symlink to a valid file at default path"
ln -s /etc/maki/attach/demo.toml /etc/maki/attach/link.toml
show $B attach --volume link --plan; show $B cleanup --volume link
echo "=== 9. state dir present after a root verb; nobody again"
ls -la /run/maki-attach 2>&1
for v in attach verify cleanup; do show as_nobody $B $v --volume demo; done
