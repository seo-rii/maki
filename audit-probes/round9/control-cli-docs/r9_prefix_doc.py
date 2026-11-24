"""(successor) docs/random-plaintext-prefix.md example, run as written (merged into a complete
config), then the documented refusals on an existing volume. Run with /usr/bin/python3.12."""
import sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk


def run(*a):
    r = subprocess.run(a, capture_output=True, text=True, timeout=120)
    return r.returncode, (r.stdout + r.stderr).strip()


v = mk.Vol(tag="r9pfx", unit=4096)
try:
    t = v.text
    t = t.replace('crypto_compatibility_id = "local-profile-v1"',
                  'crypto_compatibility_id = "local-gcm-siv-v1"\nrandom_prefix_bytes = 32')
    t = t.replace("supported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4160",
                  'supported_plaintext_sizes = [4128]\nmax_ciphertext_size = 4156\nintegrity = "verified"\ncontext_binding = "verified"\nreplay_protection = "none"')
    assert "4128" in t and "random_prefix_bytes = 32" in t, t
    open(v.cfg, "w").write(t)
    print("create:", run(mk.MAKI, "volume", "create", v.cfg))
    rc, out = run(mk.MAKI, "volume", "inspect", v.cfg)
    print("inspect rc", rc, [l for l in out.splitlines() if "compat" in l.lower() or "slot" in l.lower()])
    v.start(timeout=60)
    h = mk.connect(v.sock)
    h.pwrite(mk.pattern(0, 8192, 1), 0); h.flush()
    print("read back ok:", h.pread(8192, 0) == mk.pattern(0, 8192, 1))
    h.shutdown(); print("term", v.term())
    print("check --deep:", run(mk.MAKI, "check", v.cfg, "--deep")[1].splitlines()[-1])
    for label, text in (
        ("prefix 48 (sizes adjusted)", t.replace("random_prefix_bytes = 32", "random_prefix_bytes = 48").replace("[4128]", "[4144]").replace("4156", "4172")),
        ("prefix removed (sizes adjusted)", t.replace("random_prefix_bytes = 32\n", "").replace("[4128]", "[4096]").replace("4156", "4124")),
        ("prefix 0 (sizes adjusted)", t.replace("random_prefix_bytes = 32", "random_prefix_bytes = 0").replace("[4128]", "[4096]").replace("4156", "4124")),
        ("derived id as configured id, prefix removed", t.replace("random_prefix_bytes = 32\n", "").replace('"local-gcm-siv-v1"', '"maki-random-prefix-v1:32:local-gcm-siv-v1"').replace("[4128]", "[4096]").replace("4156", "4124")),
    ):
        open(v.cfg, "w").write(text)
        try:
            v.start(timeout=30); print(f"[{label}] daemon READY (not refused!)"); v.term()
        except RuntimeError as e:
            print(f"[{label}] daemon:", str(e).split("before READY: ")[-1].strip()[-300:])
            try: v.notify.close()
            except Exception: pass
        print(f"[{label}] check:", run(mk.MAKI, "check", v.cfg)[1][-300:])
    long_base = "x" * 100
    for n in (103, 104):
        base = "b" * n
        text = t.replace('"local-gcm-siv-v1"', f'"{base}"')
        open(v.cfg + ".long", "w").write(text)
        print(f"base id length {n} (derived {len('maki-random-prefix-v1:32:') + n}):", run(mk.MAKI, "check", v.cfg + ".long")[1][-200:])
finally:
    v.cleanup()
