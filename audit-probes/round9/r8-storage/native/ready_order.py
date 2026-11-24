import sys, os, re, time
import mk
v = mk.Vol("ro", discard=False, size="2MiB", unit=4096, shard="64KiB", seg="64KiB", jmax="512KiB")
v.create(); v.start(); h = mk.connect(v.sock)
for i in range(8):
    h.pwrite(mk.pattern(i * 65536, 4096, i + 1), i * 65536)
h.flush(); h.shutdown(); v.kill9()
trace = os.path.join(v.dir, "t.trace")
v.start(wrapper=["strace", "-f", "-y", "-qq", "-e", "trace=fsync,fdatasync,sendto,sendmsg,ftruncate,unlinkat", "-o", trace])
time.sleep(1.0)
v.kill9()
lines = open(trace).read().splitlines()
n = 0
for l in lines:
    if "fsync(" in l and "fdatasync" not in l:
        n += 1
        tag = f"fsync#{n}"
    else:
        tag = ""
    short = re.sub(r"/tmp/a9n/[^/>]*/volume", "<root>", l)[:150]
    if "READY" in l or "sendto" in l or "sendmsg" in l or n >= max(0, 0) and tag:
        print(tag, short)
print("total lines", len(lines))
v.cleanup()
