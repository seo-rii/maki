#!/bin/bash
# Run inside the CentOS Stream 9 root: package transactions around the dnf
# protection file, the conflicts and %preun, from the published v0.1.0-rc.1 RPM
# (/root/maki-rc1.rpm) to two packages built from the audited tree's packaging
# (/root/maki-0.1.0~rc.2.rpm, ~rc.3.rpm; the published binaries inside).
RC1=/root/maki-rc1.rpm; RC2=/root/maki-0.1.0~rc.2.rpm; RC3=/root/maki-0.1.0~rc.3.rpm
say() { printf '\n##### %s\n' "$*"; }
run() { printf '\n$ %s\n' "$*"; "$@" 2>&1 | grep -v '^Last metadata expiration' ; printf '[exit %s]\n' "${PIPESTATUS[0]}"; }
state() {
  printf '\n-- state: '; rpm -q maki nbdkit-server lvm2 xfsprogs kmod 2>&1 | tr '\n' ' '; echo
  printf -- '-- protected.d: '; ls -A /etc/dnf/protected.d 2>&1 | tr '\n' ' '; echo
  printf -- '-- rpm -V maki: '; rpm -V maki 2>&1 | tr '\n' ';'; echo "[exit $?]"
}
say "A. the published rc.1, as the guide installs it"
run dnf install -y -q $RC1
state
run rpm -q --provides maki
run rpm -q --conflicts maki
say "B. upgrade rc.1 -> rc.2 (dnf upgrade)"
run dnf upgrade -y -q $RC2
state
run rpm -q --provides maki
run rpm -q --conflicts maki
run rpm -qc maki
run cat /etc/dnf/protected.d/maki.conf
say "B1. removals dnf must refuse (--assumeno: nothing is changed either way)"
for p in maki lvm2 nbdkit-server xfsprogs kmod util-linux gawk coreutils-single systemd device-mapper device-mapper-libs device-mapper-event libaio kmod-libs lvm2-libs; do
  run dnf remove --assumeno $p
done
run dnf autoremove --assumeno
run dnf install --assumeno nbdkit
run dnf install --assumeno --allowerasing nbdkit
run dnf install --assumeno nbdkit-basic-plugins
say "C. downgrade rc.2 -> rc.1 (dnf downgrade)"
run dnf downgrade -y -q $RC1
state
run dnf remove --assumeno maki
say "D. upgrade rc.1 -> rc.3, reinstall, downgrade to rc.2, upgrade to rc.3"
run dnf upgrade -y -q $RC3
state
run dnf reinstall -y -q $RC3
state
run dnf downgrade -y -q $RC2
state
run dnf upgrade -y -q $RC3
state
run dnf history list
say "D1. undo of the last upgrade (a downgrade) and of the first installation (a removal), --assumeno"
last=$(dnf history list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1; exit}')
run dnf history undo --assumeno "$last"
run dnf history undo --assumeno 3
say "E. an attachment record"
mkdir -p /run/maki-attach; echo '{}' > /run/maki-attach/demo.nbd
run dnf remove --assumeno maki
run rpm -e maki
state
run dnf reinstall -y -q $RC3
state
run dnf downgrade -y -q $RC2
state
run dnf upgrade -y -q $RC3
state
run dnf downgrade -y -q $RC1
state
run dnf upgrade -y -q $RC3
state
say "F. an edited protection file (a comment appended), under the record"
echo '# local note' >> /etc/dnf/protected.d/maki.conf
state
run rpm -e maki
state
rm -f /run/maki-attach/demo.nbd
say "F1. the edited file across downgrade to rc.2 and upgrade to rc.3"
run dnf downgrade -y -q $RC2
state
run dnf upgrade -y -q $RC3
state
say "F2. rpm -e with the edited file, no record"
run rpm -e maki
state
run ls -la /etc/dnf/protected.d
run dnf autoremove --assumeno
say "F3. reinstall after the erase that left a saved copy"
run dnf install -y -q $RC3
state
run ls -la /etc/dnf/protected.d
run dnf remove --assumeno maki
say "G. the protection switched off by the administrator (maki commented out), then an upgrade"
run dnf downgrade -y -q $RC2
sed -i 's/^maki$/# maki/' /etc/dnf/protected.d/maki.conf
run dnf upgrade -y -q $RC3
state
run ls -la /etc/dnf/protected.d
run dnf remove --assumeno maki
say "H. the protection file deleted by the administrator, then an upgrade and a reinstall"
rm -f /etc/dnf/protected.d/maki.conf /etc/dnf/protected.d/maki.conf.rpm*
run dnf downgrade -y -q $RC2
state
run dnf upgrade -y -q $RC3
state
run dnf reinstall -y -q $RC3
state
say "I. downgrade to rc.1 with an edited protection file: what is left behind"
rm -f /etc/dnf/protected.d/maki.conf*; run dnf reinstall -y -q $RC3
echo '# local note' >> /etc/dnf/protected.d/maki.conf
run dnf downgrade -y -q $RC1
state
run ls -la /etc/dnf/protected.d
run dnf remove --assumeno maki
say "J. final cleanup: rpm -e, autoremove offer"
run rpm -e maki
state
run ls -la /etc/dnf/protected.d
