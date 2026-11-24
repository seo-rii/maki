"""Accepted-but-extreme configurations under the real daemon; control socket placed inside the backing tree;
missing witness directory wording."""
import sys, os, json, subprocess, shutil, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
MAKI_CHECK = os.path.join(os.path.dirname(mk.MAKI), "maki-check")
def run(*a):
    r = subprocess.run(a, capture_output=True, text=True, timeout=120); return r.returncode, (r.stdout + r.stderr).strip()
def life(tag, **kw):
    v = mk.Vol(tag=tag, **kw)
    try:
        rc, out = run(mk.MAKI, "volume", "create", v.cfg)
        if rc: print(f"[{tag}] create refused: {out[-300:]}"); return
        try: v.start(timeout=60)
        except RuntimeError as e:
            print(f"[{tag}] attach failed: {str(e)[-400:]}"); return
        h = mk.connect(v.sock)
        for i in range(32): h.pwrite(mk.pattern(i * 4096, 4096, 1), i * 4096)
        h.flush()
        print(f"[{tag}] served; checkpoint:", ctl.call(v.control, {"command": "checkpoint"}), "rss_kb", ctl.rss_kb(v.proc.pid), "threads", ctl.nthreads(v.proc.pid))
        assert h.pread(4096, 0) == mk.pattern(0, 4096, 1)
        h.pwrite(mk.pattern(0, 4096, 2), 0); h.flush()
        v.kill9()
        print(f"[{tag}] after kill -9: root entries {sorted(os.listdir(v.root))}; journal {sorted(os.listdir(os.path.join(v.root, 'journal')))}")
        for cmd in ([mk.MAKI, "check", v.cfg], [mk.MAKI, "check", v.cfg, "--deep"], [MAKI_CHECK, v.root, "--deep"]):
            rc, out = run(*cmd); print(f"[{tag}] {' '.join(os.path.basename(c) for c in cmd[:2])} {cmd[-1] if cmd[-1].startswith('--') else ''} rc={rc}: {out.splitlines()[-1][:160]} | errors: {[l[:160] for l in out.splitlines() if l.startswith(('ERROR', 'error', 'warning'))][:3]}")
        try:
            v.start(timeout=60); h = mk.connect(v.sock)
            print(f"[{tag}] restart ok; block0 v2:", h.pread(4096, 0) == mk.pattern(0, 4096, 2)); h.shutdown(); print(f"[{tag}] term rc", v.term())
            print(f"[{tag}] after clean stop: journal {sorted(os.listdir(os.path.join(v.root, 'journal')))} root {sorted(os.listdir(v.root))}")
        except RuntimeError as e:
            print(f"[{tag}] RESTART FAILED: {str(e)[-500:]}")
    finally:
        v.cleanup()

which = set(sys.argv[1:]) or {"extreme", "sock", "witness"}
if "extreme" in which:
    life("xcb", extra_limits="max_active_callbacks = 4294967295")
    life("xov", extra_limits="max_overlay_entries = 18446744073709551615\nmax_overlay_bytes = \"16777215TiB\"")
    life("xjm", jmax="18446744073709551615")
    life("xth", extra_nbd="threads = 256")
    life("xth1", extra_nbd="threads = 1")
if "sock" in which:
    # control socket inside the backing tree: accepted by validation
    for where in ("journal/x.sock", "data/x.sock", "checkpoint/x.sock", "x.sock"):
        v = mk.Vol(tag="sockin")
        try:
            text = v.text.replace(f'socket = "{v.control}"', f'socket = "{v.root}/{where}"')
            open(v.cfg, "w").write(text); v.control = f"{v.root}/{where}"
            rc, out = run(mk.MAKI, "volume", "create", v.cfg); print(f"[{where}] create rc={rc} {out[-200:] if rc else ''}")
            if rc: continue
            try: v.start(timeout=30)
            except RuntimeError as e: print(f"[{where}] attach failed: {str(e)[-300:]}"); continue
            h = mk.connect(v.sock)
            for i in range(40): h.pwrite(mk.pattern(i * 4096, 4096, 1), i * 4096)
            h.flush(); print(f"[{where}] status via socket:", ctl.status(v.control)["state"], "checkpoint:", ctl.call(v.control, {"command": "checkpoint"})["ok"])
            h.pwrite(mk.pattern(0, 4096, 2), 0); h.flush()
            v.kill9()
            print(f"[{where}] after kill -9: {sorted(os.listdir(os.path.dirname(v.control)))}")
            for cmd in ([mk.MAKI, "check", v.cfg], [mk.MAKI, "check", v.cfg, "--deep"]):
                rc, out = run(*cmd); print(f"[{where}] check{' --deep' if len(cmd) == 4 else ''} rc={rc}: {[l[:200] for l in out.splitlines() if l.startswith(('ERROR', 'error', 'warning', 'check'))][:4]}")
            try:
                v.start(timeout=30); h = mk.connect(v.sock); print(f"[{where}] restart ok, data ok: {h.pread(4096, 0) == mk.pattern(0, 4096, 2)}"); h.shutdown(); v.term()
            except RuntimeError as e:
                print(f"[{where}] RESTART FAILED: {str(e)[-400:]}")
            rc, out = run(mk.MAKI, "check", v.cfg, "--deep"); print(f"[{where}] check --deep after clean stop rc={rc}: {[l[:200] for l in out.splitlines() if l.startswith(('ERROR', 'error', 'warning', 'check'))][:4]}")
        finally:
            v.cleanup()
if "witness" in which:
    wit = f"/dev/shm/a9c-witness-{os.getpid()}"; empty = wit + "-empty"; missing = wit + "-missing"
    v = mk.Vol(tag="wit")
    try:
        prot = v.text.replace("[limits]", f'[backing.rollback_protection]\nwitness_root = "{wit}"\ncapacity = "64MiB"\n[limits]').replace('journal_emergency_reserve_bytes = "0B"', 'journal_emergency_reserve_bytes = "0B"\ncheckpoint_reserve_bytes = "0B"')
        open(v.cfg, "w").write(prot)
        rc, out = run(mk.MAKI, "volume", "create", v.cfg); print("create protected rc", rc)
        os.makedirs(empty)
        for name, text in (("witness_root -> existing empty directory", prot.replace(wit, empty)), ("witness_root -> directory that does not exist", prot.replace(wit, missing))):
            open(v.cfg, "w").write(text)
            print(f"-- {name}")
            for label, cmd in (("maki check", [mk.MAKI, "check", v.cfg]), ("maki volume inspect", [mk.MAKI, "volume", "inspect", v.cfg]), ("maki volume create", [mk.MAKI, "volume", "create", v.cfg])):
                rc, out = run(*cmd); print(f"   {label}: rc={rc}: {out[-330:]}")
            try: v.start(timeout=30); print("   daemon: READY ?!"); v.term()
            except RuntimeError as e:
                print("   daemon:", str(e).split("before READY: ")[-1].strip()[-330:])
                try: v.notify.close()
                except Exception: pass
            print("   missing dir exists now:", os.path.exists(missing))
    finally:
        v.cleanup()
        for d in (wit, empty, missing): shutil.rmtree(d, ignore_errors=True)
