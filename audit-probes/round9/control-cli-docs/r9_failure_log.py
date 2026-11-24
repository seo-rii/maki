"""(successor) Are refused requests after `drain` logged (plugin.rs fail(): one WARN per second)?
Writes spaced 1.3 s apart after a drain; then the log is read."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
v = mk.Vol(tag="r9flog")
try:
    v.create(); v.start(timeout=60); h = mk.connect(v.sock)
    h.pwrite(mk.pattern(0, 4096, 1), 0); h.flush()
    print("drain:", ctl.call(v.control, {"command": "drain"}, timeout=60))
    for i in range(4):
        try: h.pwrite(mk.pattern(0, 4096, 2), 0); r = "ok"
        except Exception as e: r = str(e)[-60:]
        try: h.flush(); f = "ok"
        except Exception as e: f = str(e)[-60:]
        print(f"write {i}: {r} | flush: {f}"); time.sleep(1.3)
    try: print("read after drain:", h.pread(4096, 0) == mk.pattern(0, 4096, 1))
    except Exception as e: print("read after drain:", str(e)[-60:])
    print("status:", {k: ctl.status(v.control).get(k) for k in ("state", "io_state")})
    h.shutdown(); print("term", v.term())
    log = v.read_log().splitlines()
    print("daemon log lines:", len(log))
    for l in log: print("  LOG:", l[:260])
finally:
    v.cleanup()
