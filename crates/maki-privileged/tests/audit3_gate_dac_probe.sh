#!/bin/bash
# Probe: the workload verify gate (ExecStartPre=!) runs as uid 0 but inherits the
# workload unit's CapabilityBoundingSet=. Opening a workload-owned 0700 mount root
# needs CAP_DAC_READ_SEARCH/CAP_DAC_OVERRIDE; workload_verify.rs only retries O_NOATIME on EPERM.
D=/var/tmp/maki-audit3-cli/mroot; rm -rf $D; mkdir -p $D; echo uuid > $D/.maki-sentinel
chmod 0644 $D/.maki-sentinel; chown 65534:65534 $D; chmod 0700 $D
setpriv --bounding-set -dac_override,-dac_read_search,-fowner --inh-caps -all -- python3 -c "
import os
for flags in (os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NOATIME, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW):
    try: os.open('$D', flags); print('open ok')
    except Exception as e: print('ERR', e)
"
