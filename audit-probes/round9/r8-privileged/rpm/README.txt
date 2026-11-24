Round-9 audit, slug r8-privileged: RPM (#384) probe in a CentOS Stream 9 root.

Re-run (root, network to mirror.stream.centos.org; about 25 minutes, most of it two rpmbuild runs of a 97 MB package):
  W=/home/user/tgt/audit9-r8priv            # any new directory
  bash mkroot.sh $W                          # dnf --installroot, key fingerprint checked
  cp <scratchpad>/audit8-installed-packages/dl/maki-0.1.0-rc.1-el9-x86_64.rpm $W/root/root/maki-rc1.rpm   # the published RPM
  bash in.sh $W dnf install -y -q rpm-build python3 gawk findutils diffutils
  mkdir -p $W/rc1 $W/root/build/release $W/root/src
  (cd $W/rc1 && rpm2cpio $W/root/root/maki-rc1.rpm | cpio -idm --quiet)
  cp $W/rc1/usr/bin/maki $W/rc1/usr/bin/maki-attach $W/rc1/usr/bin/maki-check $W/root/build/release/
  cp $W/rc1/usr/lib/maki/maki-nbdkit.so $W/root/build/release/libmaki_nbdkit.so
  mount --bind -o ro /home/user/wt/audit9 $W/root/src; mount -o remount,bind,ro $W/root/src
  EPOCH=$(git -C /home/user/wt/audit9 log -1 --format=%ct)
  for v in 0.1.0~rc.2 0.1.0~rc.3; do bash in.sh $W env SOURCE_DATE_EPOCH=$EPOCH python3 -B /src/packaging/rpm/build-rpm.py \
      --release-dir /build/release --version "$v" --architecture x86_64 --output /root/maki-$v.rpm; done
  cp transactions.sh $W/root/root/ && bash in.sh $W bash /root/transactions.sh > transactions.out 2>&1
  umount $W/root/src; bash teardown.sh $W
Outputs of the audit's run: mkroot.log, install-build-tools.log, transactions.out, built-rpms.sha256.
