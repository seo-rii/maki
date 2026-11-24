#!/usr/bin/python3.12
"""Successor probe: what a serving local authority answers after its remote.state changes,
is emptied, stops decoding or disappears under the held lock (docs/remote-witness-service.md:
'also makes it answer unavailable until a restart')."""
import os, sys, shutil, subprocess, json
import mk9 as mk, rw

base = os.path.join(mk.BASE, f"statechg-{os.getpid()}")
os.makedirs(base)
other = rw.Authority(os.path.join(base, "other"), os.path.join(base, "other-state"))
other.init()
for case in ("replaced by another valid record", "emptied", "garbage bytes", "removed"):
    a = rw.Authority(os.path.join(base, case.replace(" ", "-")), os.path.join(base, case.replace(" ", "-") + "-state"), pki=other.pki)
    a.init()
    a.start()
    cfg = a.client_config(os.path.join(a.base, "client.toml"))
    def inspect():
        r = subprocess.run([mk.WITNESS, "inspect", cfg], capture_output=True, text=True)
        return r.returncode, (r.stderr.strip() or r.stdout.strip()[:60])
    first = inspect()
    st = os.path.join(a.state, "remote.state")
    if case == "replaced by another valid record":
        shutil.copy(os.path.join(other.state, "remote.state"), st + ".tmp"); os.rename(st + ".tmp", st)
    elif case == "emptied":
        open(st, "w").close()
    elif case == "garbage bytes":
        b = bytearray(open(st, "rb").read()); b[60] ^= 0xff; open(st, "wb").write(b)
    else:
        os.unlink(st)
    after = [inspect() for _ in range(3)]
    print(f"{case}: before rc={first[0]}; after the change: " + " | ".join(f"rc={rc} {msg}" for rc, msg in after))
    a.kill9()
shutil.rmtree(base, ignore_errors=True)
