# Maki for RHEL 9 and its rebuilds (CentOS Stream 9, Rocky Linux 9,
# AlmaLinux 9). Nothing is compiled here: packaging/rpm/build-rpm.py checks
# the release artifacts, stages them with the files the Debian package
# installs, and defines the macros below. Build with that script, not with
# rpmbuild directly.

%{!?maki_version:%{error:maki_version is not defined: build with packaging/rpm/build-rpm.py}}
%{!?maki_release:%{error:maki_release is not defined: build with packaging/rpm/build-rpm.py}}
%{!?maki_stage:%{error:maki_stage is not defined: build with packaging/rpm/build-rpm.py}}
%{!?maki_autoreq:%{error:maki_autoreq is not defined: build with packaging/rpm/build-rpm.py}}

# The package carries the release artifacts byte for byte, as the Debian
# package does: no stripping, debuginfo split, build-id links, byte
# compilation, shebang mangling or man page recompression.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
# The plugin is loaded by nbdkit only; it is not a library for other packages.
%global __provides_exclude_from ^/usr/lib/maki/
# The user and groups of sysusers.d/maki.conf are provided explicitly below.
# rpm's sysusers generator (systemd-rpm-macros) would add them only on a build
# host that has it: a RHEL 9 host does, the minimal container image does not.
%global __sysusers_provides %{nil}

Name:           maki
Version:        %{maki_version}
Release:        %{maki_release}
Summary:        Encrypted block storage daemon and recovery controller
# Maki's own license. The statically linked crates keep theirs; their
# notices are collected in /usr/share/doc/maki/copyright.
License:        Apache-2.0
URL:            https://github.com/seo-rii/maki
Packager:       Maki Developers <me@seorii.page>
# On (the default) rpm adds the binaries' shared-library requirements.
AutoReq:        %{maki_autoreq}

# The installed maki@.service runs /usr/sbin/nbdkit, which nbdkit-server
# provides on EL9; the nbdkit metapackage adds plugins Maki does not use.
Requires:       nbdkit-server
Requires:       lvm2
Requires:       xfsprogs
Requires:       util-linux
Requires:       systemd >= 249
Requires:       kmod
# nbdkit-selinux labels /usr/sbin/nbdkit nbdkit_exec_t, and the targeted
# policy then gives systemd neither a transition for that type nor permission
# to execute it: maki@ could not start on an enforcing host. Only the nbdkit
# metapackage pulls the module in, wherever the targeted policy is or becomes
# installed; refuse both at install time instead. The conflict with the
# module alone is not enough: Maki is a protected package (see %files), and
# `dnf install --allowerasing nbdkit` then satisfies the metapackage by
# replacing selinux-policy-targeted with another policy.
Conflicts:      nbdkit-selinux
Conflicts:      nbdkit
# What sysusers.d/maki.conf creates, in the form rpm's sysusers generator
# gives other EL9 packages, for packages that require the user or a group.
Provides:       user(maki)
Provides:       group(maki)
Provides:       group(maki-admin)
# The owner of the binaries' ELF interpreter on the build host (glibc):
# rpm's dependency generator does not read PT_INTERP.
%{?maki_loader_requires:Requires: %{maki_loader_requires}}
Requires(post): systemd
Requires(preun): systemd
Requires(preun): coreutils
Requires(preun): gawk
Requires(postun): systemd

%description
Maki exposes encrypted backing storage through nbdkit and provides a
fail-closed privileged helper for NBD, LVM, XFS, and workload recovery.

%prep

%build

%install
cp -pR %{maki_stage}/. %{buildroot}/

%post
set -e
systemd-sysusers /usr/lib/sysusers.d/maki.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/maki.conf
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
exit 0

%preun
# Removal refuses while any volume is attached (R4-003, R5-015), exactly as
# the Debian package's prerm does: the helper the lifecycle needs for cleanup
# is part of this package. $1 is 0 when the package is erased and 1 when an
# upgrade replaces it; upgrades are deliberately exempt, and a running
# attachment must never be stopped by a package script.
set -e
if [ "$1" -eq 0 ]; then
    state_dir="${MAKI_ATTACH_STATE_DIR:-/run/maki-attach}"
    systemctl_bin="${MAKI_SYSTEMCTL:-systemctl}"
    busy=""
    for record in "$state_dir"/*.nbd; do
        if [ -e "$record" ]; then
            busy="$busy attachment-record:$(basename "$record" .nbd)"
        fi
    done
    if [ -n "${MAKI_SYSTEMCTL:-}" ] || [ -d /run/systemd/system ]; then
        # A failed query proves nothing about the units: refuse rather
        # than read its empty output as "idle".
        if listed=$("$systemctl_bin" list-units --plain --no-legend \
            --state=active,activating,reloading,deactivating \
            'maki@*.service' 'maki-attach@*.service' 'maki-recover@*.service' \
            'maki-workload@*.target' 2>/dev/null); then
            for unit in $(printf '%%s\n' "$listed" | awk '{print $1}'); do
                busy="$busy unit:$unit"
            done
        else
            busy="$busy systemd-unit-query-failed"
        fi
    fi
    if [ -n "$busy" ]; then
        echo "maki: refusing to remove the package while volumes are attached:$busy" >&2
        echo "maki: for each volume stop workloads, then deactivate its lifecycle target" \
            "maki-workload@<volume>.target: unmount/detach while the daemon still accepts I/O," \
            "then let daemon shutdown perform the final drain/checkpoint. Wait for" \
            "maki-attach@, maki-recover@ and maki@ to become inactive, and retry the removal" >&2
        exit 1
    fi
fi
exit 0

%postun
set -e
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
exit 0

%files
%defattr(0644,root,root,0755)
# dnf refuses, before it changes anything, a transaction that would remove a
# package named in /etc/dnf/protected.d or break its dependencies. %%preun can
# only keep Maki itself: rpm goes on with the rest of a transaction, which
# used to erase nbdkit-server, lvm2, xfsprogs and kmod as unused dependencies
# under an attached volume. `rpm -e maki` is the way to remove the package.
%config(noreplace) /etc/dnf/protected.d/maki.conf
%attr(0755,root,root) /usr/bin/maki
%attr(0755,root,root) /usr/bin/maki-attach
%attr(0755,root,root) /usr/bin/maki-check
%dir /usr/lib/maki
%attr(0755,root,root) /usr/lib/maki/maki-nbdkit.so
/usr/lib/systemd/system/maki@.service
/usr/lib/systemd/system/maki-attach@.service
/usr/lib/systemd/system/maki-recover@.service
/usr/lib/systemd/system/maki-workload@.target
/usr/lib/sysusers.d/maki.conf
/usr/lib/tmpfiles.d/maki.conf
%dir /usr/share/doc/maki
%dir /usr/share/doc/maki/examples
%dir /usr/share/doc/maki/examples/maki-workload.service.d
%dir /usr/share/doc/maki/examples/maki@.service.d
/usr/share/doc/maki/examples/attach.toml
/usr/share/doc/maki/examples/maki-crypto.proto
/usr/share/doc/maki/examples/maki-workload.service.d/10-maki.conf
/usr/share/doc/maki/examples/maki@.service.d/20-memory-budget.conf
/usr/share/doc/maki/examples/postgres-prod.toml
/usr/share/doc/maki/NEWS.gz
# License files stay installed when documentation is excluded (nodocs).
%license /usr/share/doc/maki/copyright
%dir /usr/share/licenses/maki
%license /usr/share/licenses/maki/LICENSE
/usr/share/man/man8/maki.8.gz
/usr/share/man/man8/maki-attach.8.gz
/usr/share/man/man8/maki-check.8.gz

%changelog
* %{maki_changelog_date} Maki Developers <me@seorii.page> - %{maki_version}-%{maki_release}
- Build Maki from the supplied release artifacts. See NEWS.gz for upstream
  changes.
