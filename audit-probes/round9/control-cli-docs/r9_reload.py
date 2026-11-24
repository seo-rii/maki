"""(successor) maki reload cache on a volume without a [cache] section and with one."""
import sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
for label, cache in (("no [cache] section", None), ("[cache] max_bytes 4MiB", 'max_bytes = "4MiB"')):
    v = mk.Vol(tag="r9rl", cache=cache)
    try:
        v.create(); v.start(timeout=60)
        for args in (["cache", "--max-bytes", "1048576"], ["cache", "--max-bytes", "0"], ["cache", "--max-bytes", "1048576", "--ttl", "5s"], ["limits"], ["crypto"]):
            r = subprocess.run([mk.MAKI, "reload", v.cfg, *args], capture_output=True, text=True)
            print(f"[{label}] maki reload {' '.join(args)} -> rc={r.returncode} {(r.stdout + r.stderr).strip()[:300]!r}")
        v.term()
    finally:
        v.cleanup()
