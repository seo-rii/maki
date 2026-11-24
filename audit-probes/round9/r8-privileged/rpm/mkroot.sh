#!/bin/bash
# Build a CentOS Stream 9 root with dnf --installroot (BaseOS + AppStream from
# mirror.stream.centos.org, key fingerprint checked), as the round-8 probe did.
# Usage: mkroot.sh <new-work-dir>
set -euo pipefail
work=$(realpath -m "$1"); [ ! -e "$work" ] || { echo "$work exists" >&2; exit 1; }
D=$work/dnf; root=$work/root; mkdir -p "$D/repos" "$D/home" "$D/keys"
curl -fsSLo "$D/keys.rpm" https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/Packages/centos-gpg-keys-9.0-38.el9.noarch.rpm
(cd "$D/keys" && rpm2cpio ../keys.rpm | cpio -idm --quiet)
cp "$D/keys/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial" "$D/"
test "$(GNUPGHOME="$(mktemp -d)" gpg --show-keys --with-colons "$D/RPM-GPG-KEY-centosofficial" 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')" = 99DB70FAE1D7CE227FB6488205B555B38483C65D
printf '[main]\ngpgcheck=1\nbest=True\nskip_if_unavailable=False\ninstall_weak_deps=False\nkeepcache=False\n' > "$D/dnf.conf"
for r in BaseOS AppStream; do
  printf '[c9s-%s]\nname=CentOS Stream 9 - %s\nbaseurl=https://mirror.stream.centos.org/9-stream/%s/x86_64/os/\ngpgcheck=1\ngpgkey=file://%s/RPM-GPG-KEY-centosofficial\nenabled=1\n\n' "$r" "$r" "$r" "$D"
done > "$D/repos/c9s.repo"
printf '%%_dbpath /var/lib/rpm\n%%_db_backend sqlite\n' > "$D/home/.rpmmacros"
py=python3; for candidate in python3 /usr/bin/python3 python3.12 python3.11; do if "$candidate" -c "import libdnf" 2>/dev/null; then py=$candidate; break; fi; done
HOME="$D/home" "$py" /usr/bin/dnf -y -q --config="$D/dnf.conf" --setopt=reposdir="$D/repos" \
  --installroot="$root" --releasever=9 --forcearch=x86_64 --nodocs \
  install bash coreutils-single dnf centos-stream-release centos-stream-repos centos-gpg-keys glibc-minimal-langpack rootfiles
sed -i 's#^metalink=https://mirrors.centos.org/metalink?repo=centos-baseos-$stream.*#baseurl=https://mirror.stream.centos.org/9-stream/BaseOS/$basearch/os/#; s#^metalink=https://mirrors.centos.org/metalink?repo=centos-appstream-$stream.*#baseurl=https://mirror.stream.centos.org/9-stream/AppStream/$basearch/os/#' "$root/etc/yum.repos.d/centos.repo"
sed -i 's/^enabled=1/enabled=0/' "$root/etc/yum.repos.d/centos-addons.repo"
if [ -n "${HTTPS_PROXY:-}" ]; then
  cp /root/.ccr/ca-bundle.crt "$root/etc/sandbox-proxy-ca.pem"
  printf 'proxy=%s\nsslcacert=/etc/sandbox-proxy-ca.pem\n' "$HTTPS_PROXY" >> "$root/etc/dnf/dnf.conf"
fi
cp /etc/resolv.conf "$root/etc/resolv.conf"
echo "root ready: $root"
