#!/bin/bash
set -uo pipefail
run() { echo "--- $*"; "$@"; echo "exit=$?"; }
bash /root/run/start-daemon.sh demo >/dev/null; sleep 3; tail -1 /root/run/notify.log
run maki-attach attach --volume demo --plan
run maki-attach verify --volume demo --plan
run maki-attach grow --volume demo --size-bytes 7516192768 --plan
run maki-attach attach --volume demo
ls -la /run/maki-attach
run maki-attach attach --volume demo --nbd-device /dev/nbd0
run maki-attach nbd-connect --nbd-device /dev/nbd0 --socket /run/maki/demo/nbd.sock --block-size 4096 --identifier maki-bootstrap-11111111-2222-4333-8444-555555555555 --plan
run maki-attach nbd-connect --nbd-device /dev/nbd0 --socket /run/maki/demo/nbd.sock --block-size 4096 --identifier maki-bootstrap-11111111-2222-4333-8444-555555555555
run maki-attach nbd-disconnect --nbd-device /dev/nbd0 --identifier maki-bootstrap-11111111-2222-4333-8444-555555555555 --plan
run maki-attach nbd-disconnect --nbd-device /dev/nbd0 --identifier maki-bootstrap-11111111-2222-4333-8444-555555555555
run maki-attach nbd-connect --nbd-device /dev/nbd0 --socket /run/maki/demo/nbd.sock --identifier maki-11111111-2222-4333-8444-555555555555
run maki-attach grow --volume demo --size-bytes 7516192768
run maki-attach recover --volume demo
run maki-attach cleanup --volume demo
run maki-attach detach --volume demo
run maki-attach recover-failed-start --volume demo
ls -la /run/maki-attach
maki status /etc/maki/volumes/demo.toml | grep -E '"state"|io_state'
bash /root/run/stop-daemon.sh demo
cat /root/run/daemon-demo.log
