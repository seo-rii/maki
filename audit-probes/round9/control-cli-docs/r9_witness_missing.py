"""(successor) F1 re-run: a protected local volume whose witness directory is not there (moved
away, as after a reboot with the witness on a tmpfs or an unmounted mount point that was removed).
Every reader is run before anything could recreate the directory. Run with /usr/bin/python3.12."""
import sys, os, subprocess, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk

HERE = os.path.dirname(os.path.abspath(__file__))
MAKI_CHECK = os.path.join(HERE, "bin", "maki-check")
BENCH = os.path.join(HERE, "bin", "maki-benchmark")


def run(*a, env=None):
    e = dict(os.environ); e.update(env or {})
    r = subprocess.run(a, capture_output=True, text=True, timeout=180, env=e)
    return r.returncode, (r.stdout + r.stderr).strip()


wit = f"/dev/shm/a9c-r9wit-{os.getpid()}"
moved = wit + "-moved"
v = mk.Vol(tag="r9wit")
try:
    prot = v.text.replace("[limits]", f'[backing.rollback_protection]\nwitness_root = "{wit}"\ncapacity = "64MiB"\n[limits]')
    prot = prot.replace('journal_emergency_reserve_bytes = "0B"', 'journal_emergency_reserve_bytes = "0B"\ncheckpoint_reserve_bytes = "0B"')
    open(v.cfg, "w").write(prot)
    print("create:", run(mk.MAKI, "volume", "create", v.cfg))
    print("check with witness present:", run(mk.MAKI, "check", v.cfg))
    os.rename(wit, moved)
    print(f"-- witness directory {wit} moved away (does not exist)")
    for label, cmd in (("maki check", [mk.MAKI, "check", v.cfg]),
                       ("maki check --deep", [mk.MAKI, "check", v.cfg, "--deep"]),
                       ("maki volume inspect", [mk.MAKI, "volume", "inspect", v.cfg]),
                       ("maki check (MAKI_LOG=trace)", [mk.MAKI, "check", v.cfg]),
                       ("maki-benchmark --destroy-data", [BENCH, "--destroy-data", v.cfg, "16", "4096"])):
        env = {"MAKI_LOG": "trace"} if "trace" in label else None
        rc, out = run(*cmd, env=env)
        print(f"   {label}: rc={rc}: {out[-400:]!r}")
        assert not os.path.exists(wit), f"{label} created {wit}"
    try:
        v.start(timeout=30)
        print("   daemon: READY ?!"); v.term()
    except RuntimeError as e:
        print("   daemon:", repr(str(e).split("before READY: ")[-1].strip()[-400:]))
        try: v.notify.close()
        except Exception: pass
    print("   witness dir exists after readers:", os.path.exists(wit))
    rc, out = run(mk.MAKI, "volume", "create", v.cfg)
    print(f"   maki volume create: rc={rc}: {out[-200:]!r}")
    print("   witness dir exists after create:", os.path.exists(wit), os.listdir(wit) if os.path.exists(wit) else None)
    shutil.rmtree(wit, ignore_errors=True)
    os.rename(moved, wit)
    print("-- witness restored")
    print("check:", run(mk.MAKI, "check", v.cfg))
    v.start(timeout=30); h = mk.connect(v.sock); h.pwrite(mk.pattern(0, 4096, 1), 0); h.flush()
    print("daemon serves; read back ok:", h.pread(4096, 0) == mk.pattern(0, 4096, 1)); h.shutdown(); print("term", v.term())
finally:
    v.cleanup()
    for d in (wit, moved):
        shutil.rmtree(d, ignore_errors=True)
