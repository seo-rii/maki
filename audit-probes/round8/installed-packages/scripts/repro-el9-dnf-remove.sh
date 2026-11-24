#!/bin/bash
# Reproduce F-c from nothing: a CentOS Stream 9 root, the published RPM installed
# as the RHEL guide says, an attachment record, then the documented `dnf remove maki`.
# Usage: repro-el9-dnf-remove.sh <new-empty-work-dir>   (needs root, dnf, rpm2cpio, cpio, gpg, curl)
# The work dir is unmounted and deleted at the end.
set -euo pipefail
work=$(realpath -m "$1"); [ ! -e "$work" ] || { echo "$work exists" >&2; exit 1; }
here=$(cd "$(dirname "$0")/.." && pwd)
rpm_file=$here/dl/maki-0.1.0-rc.1-el9-x86_64.rpm
(cd "$here/dl" && sha256sum --check --ignore-missing --quiet SHA256SUMS)
D=$work/dnf; root=$work/root; mkdir -p "$D/repos" "$D/home" "$D/keys"
cleanup() {
  for m in "$root/dev" "$root/sys" "$root/proc"; do
    if mountpoint -q "$m"; then mount --make-rslave "$m" 2>/dev/null || true; umount -R "$m" || umount -l "$m"; fi
  done
  if findmnt -rn -o TARGET | grep -q "^$work/"; then echo "still mounted below $work" >&2; exit 1; fi
  rm -rf --one-file-system "$work"
}
trap cleanup EXIT
curl -fsSLo "$D/keys.rpm" https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/Packages/centos-gpg-keys-9.0-38.el9.noarch.rpm
(cd "$D/keys" && rpm2cpio ../keys.rpm | cpio -idm --quiet)
cp "$D/keys/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial" "$D/"
test "$(GNUPGHOME="$(mktemp -d)" gpg --show-keys --with-colons "$D/RPM-GPG-KEY-centosofficial" 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')" = 99DB70FAE1D7CE227FB6488205B555B38483C65D
printf '[main]\ngpgcheck=1\nbest=True\nskip_if_unavailable=False\ninstall_weak_deps=False\nkeepcache=False\n' > "$D/dnf.conf"
for r in BaseOS AppStream; do
  printf '[c9s-%s]\nname=CentOS Stream 9 - %s\nbaseurl=https://mirror.stream.centos.org/9-stream/%s/x86_64/os/\ngpgcheck=1\ngpgkey=file://%s/RPM-GPG-KEY-centosofficial\nenabled=1\n\n' "$r" "$r" "$r" "$D"
done > "$D/repos/c9s.repo"
printf '%%_dbpath /var/lib/rpm\n%%_db_backend sqlite\n' > "$D/home/.rpmmacros"
# Debian/Ubuntu build the libdnf binding for the distribution's python3 only.
py=python3; for candidate in python3 /usr/bin/python3 python3.12 python3.11; do if "$candidate" -c "import libdnf" 2>/dev/null; then py=$candidate; break; fi; done
HOME="$D/home" "$py" /usr/bin/dnf -y -q --config="$D/dnf.conf" --setopt=reposdir="$D/repos" \
  --installroot="$root" --releasever=9 --forcearch=x86_64 --nodocs \
  install bash coreutils-single dnf centos-stream-release centos-stream-repos centos-gpg-keys glibc-minimal-langpack rootfiles
# The root's own repositories: stock ids, BaseOS and AppStream only, fetched from mirror.stream.centos.org.
sed -i 's#^metalink=https://mirrors.centos.org/metalink?repo=centos-baseos-$stream.*#baseurl=https://mirror.stream.centos.org/9-stream/BaseOS/$basearch/os/#; s#^metalink=https://mirrors.centos.org/metalink?repo=centos-appstream-$stream.*#baseurl=https://mirror.stream.centos.org/9-stream/AppStream/$basearch/os/#' "$root/etc/yum.repos.d/centos.repo"
sed -i 's/^enabled=1/enabled=0/' "$root/etc/yum.repos.d/centos-addons.repo"
if [ -n "${HTTPS_PROXY:-}" ]; then
  cp /root/.ccr/ca-bundle.crt "$root/etc/sandbox-proxy-ca.pem"
  printf 'proxy=%s\nsslcacert=/etc/sandbox-proxy-ca.pem\n' "$HTTPS_PROXY" >> "$root/etc/dnf/dnf.conf"
fi
cp /etc/resolv.conf "$root/etc/resolv.conf"
mount -t proc proc "$root/proc"; mount --rbind /sys "$root/sys"; mount --make-rslave "$root/sys"; mount --rbind /dev "$root/dev"; mount --make-rslave "$root/dev"
cp "$rpm_file" "$root/root/maki.rpm"
in_root() { chroot "$root" /usr/bin/env -i HOME=/root LANG=C.UTF-8 PATH=/usr/sbin:/usr/bin "$@"; }
echo "### guide: dnf install -y ./maki.rpm"
in_root dnf install -y -q /root/maki.rpm
in_root rpm -q maki nbdkit-server lvm2 xfsprogs kmod
in_root grep clean_requirements /etc/dnf/dnf.conf || echo "(clean_requirements_on_remove: dnf default, True)"
echo "### an attachment record, then the documented removal"
in_root sh -c 'echo "{}" > /run/maki-attach/demo.nbd'
set +e
in_root dnf remove -y maki; echo "dnf remove exit=$?"
echo "### after the refused removal"
in_root rpm -q maki nbdkit-server lvm2 xfsprogs kmod
in_root rpm -V maki; echo "rpm -V maki exit=$?"
in_root ls -la /usr/sbin/nbdkit /usr/sbin/vgchange /usr/sbin/modprobe /usr/bin/maki-attach
exit 0
