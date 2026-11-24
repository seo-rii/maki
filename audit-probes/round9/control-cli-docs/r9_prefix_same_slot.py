"""(successor) prefix change that keeps max_ciphertext_size (and so the slot) unchanged: must still be refused."""
import sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk
def run(*a):
    r = subprocess.run(a, capture_output=True, text=True, timeout=120); return r.returncode, (r.stdout + r.stderr).strip()
v = mk.Vol(tag="r9pfx2", unit=4096)
try:
    t = v.text.replace('crypto_compatibility_id = "local-profile-v1"', 'crypto_compatibility_id = "local-gcm-siv-v1"\nrandom_prefix_bytes = 32')
    t = t.replace("supported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4160", 'supported_plaintext_sizes = [4128]\nmax_ciphertext_size = 4156')
    open(v.cfg, "w").write(t); print("create:", run(mk.MAKI, "volume", "create", v.cfg)[0])
    v.start(timeout=60); h = mk.connect(v.sock); h.pwrite(mk.pattern(0, 4096, 1), 0); h.flush(); h.shutdown(); v.term()
    for label, text in (("prefix 16, sizes [4112], max 4156", t.replace("random_prefix_bytes = 32", "random_prefix_bytes = 16").replace("[4128]", "[4112]")),
                        ("prefix removed, sizes [4096], max 4156", t.replace("random_prefix_bytes = 32\n", "").replace("[4128]", "[4096]"))):
        open(v.cfg, "w").write(text)
        try:
            v.start(timeout=30); print(f"[{label}] daemon READY (not refused!)"); v.term()
        except RuntimeError as e:
            print(f"[{label}] daemon:", str(e).split("before READY: ")[-1].strip()[-300:])
            try: v.notify.close()
            except Exception: pass
        rc, out = run(mk.MAKI, "check", v.cfg); print(f"[{label}] maki check rc={rc}: {out.splitlines()[-1]}")
        rc, out = run(mk.MAKI, "volume", "inspect", v.cfg); print(f"[{label}] inspect rc={rc}: {[l for l in out.splitlines() if 'compat' in l]}")
finally:
    v.cleanup()
