#!/usr/bin/python3.12
"""Start nbdkit with stdin/stdout/stderr closed (or stderr on /dev/full) and
look at what the daemon's fds 0-2 are, then make the plugin log."""
import os, sys, time, subprocess, socket, nbd, mk, errno
mode = sys.argv[1] if len(sys.argv) > 1 else "closed"
v = mk.Vol("fds")
try:
    v.create()
    npath = os.path.join(v.dir, "n.sock")
    n = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); n.bind(npath); n.settimeout(20)
    env = dict(os.environ); env["NOTIFY_SOCKET"] = npath
    cmd = ["nbdkit", "--foreground", "-U", v.sock, mk.PLUGIN, f"config={v.cfg}"]
    def pre():
        os.setsid()
        if mode == "closed":
            os.close(0); os.close(1); os.close(2)
        elif mode == "full":
            fd = os.open("/dev/full", os.O_WRONLY); os.dup2(fd, 1); os.dup2(fd, 2)
    p = subprocess.Popen(cmd, env=env, preexec_fn=pre, close_fds=True)
    try:
        print("notify:", n.recv(200))
    except socket.timeout:
        print("no READY; exit status", p.poll())
    for fd in (0, 1, 2):
        try:
            print(f"fd {fd} ->", os.readlink(f"/proc/{p.pid}/fd/{fd}"))
        except OSError as e:
            print(f"fd {fd} -> (closed) {e.strerror}")
    h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
    d = mk.pattern(0, 65536, 1); h.pwrite(d, 0, nbd.CMD_FLAG_FUA)
    # make the plugin log: refused requests are logged at WARN once per second
    for i in range(3):
        try: h.pwrite(b"x" * 100, 7)
        except nbd.Error as e: pass
        time.sleep(1.1)
    for fd in (0, 1, 2):
        try:
            print(f"fd {fd} ->", os.readlink(f"/proc/{p.pid}/fd/{fd}"))
        except OSError as e:
            print(f"fd {fd} -> (closed) {e.strerror}")
    print("data intact while running:", bytes(h.pread(65536, 0)) == d)
    h.shutdown()
    p.terminate(); print("exit status", p.wait(30))
    r = v.maki("check", v.cfg, "--deep"); print("maki check --deep rc", r.returncode, (r.stdout + r.stderr)[-400:])
    v.start()
    h = nbd.NBD(); h.connect_unix(v.sock)
    print("data intact after restart:", bytes(h.pread(65536, 0)) == d)
finally:
    v.cleanup()
