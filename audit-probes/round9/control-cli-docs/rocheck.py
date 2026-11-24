"""Offline tools on a read-only view of a healthy, cleanly stopped volume (read-only bind mount),
and as a user with read-only access to the files."""
import sys, os, subprocess, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
MAKI_CHECK = os.path.join(os.path.dirname(mk.MAKI), "maki-check")
def run(*a):
    r = subprocess.run(a, capture_output=True, text=True, timeout=120); return r.returncode, (r.stdout + r.stderr).strip()
v = mk.Vol(tag="ro")
ro = v.dir + "/ro"
try:
    v.create(); v.start(); h = mk.connect(v.sock)
    for i in range(16): h.pwrite(mk.pattern(i * 4096, 4096, 1), i * 4096)
    h.flush(); h.shutdown(); v.term()
    os.makedirs(ro)
    subprocess.run(["mount", "--bind", v.root, ro], check=True)
    subprocess.run(["mount", "-o", "remount,bind,ro", ro], check=True)
    text = v.text.replace(f'root = "{v.root}"', f'root = "{ro}"'); cfg2 = v.dir + "/ro.toml"; open(cfg2, "w").write(text); os.chmod(cfg2, 0o644)
    for label, cmd in (("maki check", [mk.MAKI, "check", cfg2]), ("maki check --deep", [mk.MAKI, "check", cfg2, "--deep"]), ("maki volume inspect", [mk.MAKI, "volume", "inspect", cfg2]), ("maki-check", [MAKI_CHECK, ro]), ("maki-check --deep", [MAKI_CHECK, ro, "--deep"])):
        rc, out = run(*cmd); print(f"read-only mount: {label}: rc={rc}: {out.splitlines()[-1][:200] if out else ''}")
    for label, cmd in (("maki check", [mk.MAKI, "check", v.cfg]), ("maki-check", [MAKI_CHECK, v.root])):
        rc, out = run(*cmd); print(f"writable original: {label}: rc={rc}: {out.splitlines()[-1][:200] if out else ''}")
finally:
    subprocess.run(["umount", ro], capture_output=True)
    v.cleanup()
