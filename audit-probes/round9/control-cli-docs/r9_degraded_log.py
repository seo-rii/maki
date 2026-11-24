"""(successor) D-draft A, clean form: only the administrative checkpoint fails (no NBD request
fails), then compare `maki status` (state degraded) with the daemon log (expect a WARN per
docs/observability.md:97-101). Same for `drain`. Run with /usr/bin/python3.12."""
import sys, os, json, time, subprocess, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl

KS = ("state", "degraded_reason", "checkpoint_failures_total", "journal_sync_failures_total",
      "durable_sequence", "checkpoint_sequence", "io_state", "drain_error")


def pick(d):
    return {k: d.get(k) for k in KS}


def inject(pid, tr):
    st = subprocess.Popen(["strace", "-f", "-qq", "-p", str(pid), "-e", "trace=fdatasync,fsync",
                           "-e", "inject=fdatasync,fsync:error=EIO", "-o", tr],
                          stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    return st


v = mk.Vol(tag="r9deg")
try:
    v.create()
    v.start(env={"MAKI_LOG": "info"})
    h = mk.connect(v.sock)
    for i in range(4):
        h.pwrite(mk.pattern(i * 4096, 4096, 1), i * 4096)
    h.flush()
    print("before:", pick(ctl.status(v.control)))
    for verb in ("checkpoint", "drain"):
        tr = os.path.join(v.dir, f"inj-{verb}.trace")
        st = inject(v.proc.pid, tr)
        r = ctl.call(v.control, {"command": verb}, timeout=60)
        st.send_signal(signal.SIGINT); st.wait()
        print(f"{verb} verb under injection:", r)
        print("  status:", pick(ctl.status(v.control)))
        cli = subprocess.run([mk.MAKI, "status", "--socket", v.control], capture_output=True, text=True)
        print("  `maki status` rc", cli.returncode, "->", [l for l in cli.stdout.splitlines() if "state" in l or "degraded" in l][:4], cli.stderr.strip()[:200])
        print("  injected syscalls:", sum(1 for l in open(tr) if "INJECTED" in l))
        log = v.read_log().splitlines()
        print("  daemon log lines so far:", len(log), "WARN/ERROR lines:", [l[:220] for l in log if " WARN " in l or " ERROR " in l])
        r = ctl.call(v.control, {"command": "checkpoint"} if verb == "checkpoint" else {"command": "drain"}, timeout=60)
        print(f"  {verb} again without injection:", r, pick(ctl.status(v.control)))
        if verb == "checkpoint":
            for i in range(4, 6):
                h.pwrite(mk.pattern(i * 4096, 4096, 1), i * 4096)
            h.flush()
    h.shutdown()
    print("term rc", v.term())
    print("FULL DAEMON LOG:")
    for line in v.read_log().splitlines():
        print("  LOG:", line[:300])
finally:
    v.cleanup()
