#!/bin/bash
# Exercise the NBD export of the running daemon from inside the root.
set -uo pipefail
vol=${1:-demo}
sock=/run/maki/$vol/nbd.sock
uri="nbd+unix:///?socket=$sock"
echo "--- nbdinfo"; nbdinfo "$uri"; echo "nbdinfo exit=$?"
echo "--- write 8 MiB of random data at offset 0 and 1 MiB at 5 GiB"
head -c 8388608 /dev/urandom > /root/run/blob-a.bin
head -c 1048576 /dev/urandom > /root/run/blob-b.bin
nbdcopy /root/run/blob-a.bin "$uri"; echo "nbdcopy write exit=$?"
python3 - "$sock" <<'PY' 2>&1 || echo "python nbd not available"
PY
# nbdcopy has no destination offset: write blob-b at 5 GiB with nbdsh if present, else skip
if command -v nbdsh >/dev/null 2>&1; then
  nbdsh -u "$uri" -c 'buf=open("/root/run/blob-b.bin","rb").read(); h.pwrite(buf, 5*1024**3, nbd.CMD_FLAG_FUA); h.flush(); print("pwrite+FUA at 5GiB ok; can_fua", h.can_fua(), "can_flush", h.can_flush(), "can_trim", h.can_trim(), "can_zero", h.can_zero(), "can_multi_conn", h.can_multi_conn(), "rotational", h.is_rotational(), "ro", h.is_read_only())'
  echo "nbdsh exit=$?"
fi
echo "--- read back"
nbdcopy --request-size=1048576 "$uri" - 2>/dev/null | head -c 8388608 | cmp - /root/run/blob-a.bin && echo "read-back of first 8 MiB matches"
if command -v nbdsh >/dev/null 2>&1; then
  nbdsh -u "$uri" -c 'buf=h.pread(1048576, 5*1024**3); import sys; exp=open("/root/run/blob-b.bin","rb").read(); print("5GiB read-back matches" if bytes(buf)==exp else "5GiB MISMATCH"); z=h.pread(4096, 3*1024**3); print("unwritten reads zeros" if bytes(z)==bytes(4096) else "unwritten NOT zeros")'
fi
