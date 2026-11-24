#!/bin/bash
# Start nbdkit as maki@<volume>.service's ExecStart does, as user maki, with as
# much of the unit's environment as a chroot allows:
#   User=/Group= (and the user's supplementary groups), RuntimeDirectory= with
#   RuntimeDirectoryMode=0711, LoadCredential= (copied, CREDENTIALS_DIRECTORY),
#   NOTIFY_SOCKET (Type=notify), NoNewPrivileges=, empty capability sets,
#   LimitCORE=0, LimitMEMLOCK=512M, the manager's default environment.
# Not emulated: ProtectSystem=, PrivateTmp=, DevicePolicy=, the seccomp filters
# (SystemCallFilter=, RestrictAddressFamilies=, MemoryDenyWriteExecute= unless
# MDWE=1 asks for the prctl approximation), namespaces, cgroups.
set -euo pipefail
vol=${1:-demo}
unit=/usr/lib/systemd/system/maki@.service
# The ExecStart line of the installed unit, continuation lines joined, %i expanded.
exec_start=$(awk '/^ExecStart=/{f=1} f{l=$0; sub(/\\$/,"",l); printf "%s ", l; if ($0 !~ /\\$/) exit}' "$unit" | sed "s/^ExecStart=//; s/%i/$vol/g")
echo "ExecStart: $exec_start"
install -d -m 0711 -o maki -g maki "/run/maki/$vol" "/run/maki-control/$vol"
cred="/run/credentials/maki@$vol.service"
rm -rf "$cred"; install -d -m 0700 -o maki -g maki "$cred"
install -m 0400 -o maki -g maki "/etc/maki/secrets/$vol.token" "$cred/crypto-token"
chmod 0500 "$cred"
if [ -f /root/run/notify.pid ]; then kill "$(cat /root/run/notify.pid)" 2>/dev/null || true; fi
setsid nohup python3 /root/run/notify-listen.py /run/maki-notify.sock /root/run/notify.log >/dev/null 2>&1 &
echo $! > /root/run/notify.pid
for i in $(seq 50); do [ -S /run/maki-notify.sock ] && break; sleep 0.1; done
wrap=()
# LimitMEMLOCK=512M needs CAP_SYS_RESOURCE, which this sandbox's root lacks:
# keep the inherited limit then and say so.
memlock=--memlock=536870912
if ! prlimit --memlock=536870912 true 2>/dev/null; then memlock=; echo "note: cannot raise RLIMIT_MEMLOCK (no CAP_SYS_RESOURCE); inherited: $(prlimit --memlock --noheadings -o SOFT,HARD)"; fi
if [ "${MDWE:-0}" = 1 ]; then wrap=(python3 /usr/local/lib/audit8/mdwe-exec.py); fi
cd /
# shellcheck disable=SC2086
setsid nohup env -i \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin LANG=C.UTF-8 \
  USER=maki LOGNAME=maki HOME=/var/lib/maki SHELL=/usr/sbin/nologin \
  RUNTIME_DIRECTORY="/run/maki/$vol:/run/maki-control/$vol" \
  CREDENTIALS_DIRECTORY="$cred" NOTIFY_SOCKET=/run/maki-notify.sock \
  prlimit --core=0 $memlock \
  setpriv --reuid maki --regid maki --init-groups --no-new-privs \
          --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
  "${wrap[@]}" $exec_start >"/root/run/daemon-$vol.log" 2>&1 &
echo $! > "/root/run/daemon-$vol.launcher.pid"
