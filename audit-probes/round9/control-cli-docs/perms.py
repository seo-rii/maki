"""Every control verb as owner / admin-group member / other user (setpriv), and what
an "other" user can learn. Daemon runs as uid nobody (65534) with supplementary group
games (60) standing in for maki-admin; nothing is added to the host."""
import sys, os, json, subprocess, shutil, stat, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl
DAEMON = ["setpriv", "--reuid", "65534", "--regid", "65534", "--groups", "60"]
ADMIN = ["setpriv", "--reuid", "12345", "--regid", "12345", "--groups", "60"]
OTHER = ["setpriv", "--reuid", "12346", "--regid", "12346", "--clear-groups"]
OWNER = ["setpriv", "--reuid", "65534", "--regid", "65534", "--clear-groups"]

base = "/tmp/a9c-perm"
shutil.rmtree(base, ignore_errors=True)
os.makedirs(base); os.chmod(base, 0o755)
os.makedirs(base + "/bin"); os.chmod(base + "/bin", 0o755)
for n in ("libmaki_nbdkit.so", "maki"):
    shutil.copy(os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", n), base + "/bin/" + n); os.chmod(base + "/bin/" + n, 0o755)
mk.PLUGIN = base + "/bin/libmaki_nbdkit.so"; mk.MAKI = base + "/bin/maki"
v = mk.Vol(tag="perm", base=base, extra_top="", cache='mode = "read"\nmax_bytes = "1MiB"\nttl = "30s"')
# rewrite config with the group; key and tree owned by the daemon user; config root-owned 0644
text = v.text.replace('[control]\n', '[control]\ngroup = "games"\n')
open(v.cfg, "w").write(text); os.chmod(v.cfg, 0o644)
os.chmod(v.dir, 0o711)
os.chown(v.dir, 65534, 65534); os.chown(v.key, 65534, 65534)
def run(who, *args, timeout=60):
    return subprocess.run(list(who) + list(args), capture_output=True, text=True, timeout=timeout)
try:
    r = run(OWNER, mk.MAKI, "volume", "create", v.cfg); print("create as daemon user:", r.returncode, r.stdout.strip(), r.stderr.strip()[:200])
    old = os.umask(0); v.start(wrapper=DAEMON, wait=False); os.umask(old); v.wait_ready(30)
    st = os.stat(v.control); print("control.sock: mode %o uid %d gid %d" % (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid))
    st = os.stat(v.sock); print("nbd.sock:     mode %o uid %d gid %d (dir mode %o)" % (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, stat.S_IMODE(os.stat(v.dir).st_mode)))
    print("backing root mode %o" % stat.S_IMODE(os.stat(v.root).st_mode), sorted(os.listdir(v.root)))
    for n in sorted(os.listdir(v.dir)):
        s = os.lstat(os.path.join(v.dir, n)); print("  %-22s %o %d:%d" % (n, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid))
    verbs = [["status"], ["metrics"], ["checkpoint"], ["reload", "cache", "--max-bytes", "4096"], ["reload", "retry"], ["drain"]]
    for name, who in (("other", OTHER), ("admin", ADMIN), ("owner", OWNER)):
        for verb in verbs:
            r = run(who, mk.MAKI, verb[0], "--socket", v.control, *verb[1:], "--timeout", "10")
            first = (r.stdout.strip().splitlines() or [""])[0:3]
            print(f"{name:6} {' '.join(verb):34} rc={r.returncode} out={' '.join(first)[:70]!r} err={r.stderr.strip()[:150]!r}")
        # config-path form (config is root:root 0644 here, readable)
        r = run(who, mk.MAKI, "status", v.cfg, "--timeout", "10"); print(f"{name:6} status <config>                    rc={r.returncode} err={r.stderr.strip()[:150]!r}")
    # what other can learn / reach
    for path in (v.control, v.sock, v.root, v.key, os.path.join(v.root, "superblock.a"), v.cfg):
        r = run(OTHER, "python3", "-c", "import os,sys,socket\np=sys.argv[1]\ntry:\n s=os.stat(p); print('stat ok mode %o'%(s.st_mode&0o7777))\nexcept Exception as e: print('stat', e)\ntry:\n open(p,'rb').read(16); print('read ok')\nexcept Exception as e: print('read', e)\ntry:\n c=socket.socket(socket.AF_UNIX); c.connect(p); print('connect ok')\nexcept Exception as e: print('connect', e)\n", path)
        print("other ->", os.path.basename(path), "|", r.stdout.strip().replace("\n", " | ")[:300])
    r = run(OTHER, "ls", "-la", v.dir); print("other ls dir:", r.returncode, r.stderr.strip()[:100])
    # admin: can it reach the NBD socket (must not: SPEC 8) -- here the dir is 0711 so traversal is allowed; nbdkit's own mode decides
    r = run(ADMIN, "python3", "-c", "import socket,sys\nc=socket.socket(socket.AF_UNIX)\ntry:\n c.connect(sys.argv[1]); print('connect ok')\nexcept Exception as e: print('connect', e)\n", v.sock)
    print("admin -> nbd.sock:", r.stdout.strip())
    # offline tools as admin/other on the live volume
    for name, who in (("other", OTHER), ("admin", ADMIN)):
        for cmd in (["check", v.cfg], ["check", v.cfg, "--deep"], ["volume", "inspect", v.cfg]):
            r = run(who, mk.MAKI, *cmd); print(f"{name:6} maki {' '.join(cmd[:1]+cmd[2:]) or cmd[0]:20} rc={r.returncode} err={r.stderr.strip()[:160]!r}")
    print("term rc", v.term())
    print(v.read_log()[-1200:])
finally:
    v.cleanup(); shutil.rmtree(base, ignore_errors=True)
