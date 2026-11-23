#!/bin/bash
S=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness
cd /home/user/tgt/audit5-tr-mut/src
ls -la scripts/__pycache__ > $S/logs/py-pycache-before.txt 2>&1
python3 -B -m unittest discover -s scripts -p 'test_*.py' > $S/logs/py-copy-base.log 2>&1; echo "base rc=$?" >> $S/logs/py.progress
ls -la scripts/__pycache__ > $S/logs/py-pycache-after.txt 2>&1
(umask 002; python3 -B -m unittest discover -s scripts -p 'test_*.py' > $S/logs/py-copy-u002.log 2>&1; echo "u002 rc=$?" >> $S/logs/py.progress)
mkdir -p /home/user/tgt/audit5-tr-tmp/py-nobody/tmp /home/user/tgt/audit5-tr-tmp/py-nobody/home; chown -R 65534:65534 /home/user/tgt/audit5-tr-tmp/py-nobody
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/home/user/tgt/audit5-tr-tmp/py-nobody/home TMPDIR=/home/user/tgt/audit5-tr-tmp/py-nobody/tmp setpriv --reuid 65534 --regid 65534 --clear-groups python3 -B -m unittest discover -s scripts -p 'test_*.py' > $S/logs/py-copy-nobody.log 2>&1; echo "nobody rc=$?" >> $S/logs/py.progress
