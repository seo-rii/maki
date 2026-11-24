"""Hostile control clients, part 2: session/backlog bounds, slow loris, unread responses,
I/O latency meanwhile, SIGTERM with stuck sessions and immediate restart."""
import sys, os, json, time, socket, resource, threading, select, subprocess, errno
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl

_soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE); resource.setrlimit(resource.RLIMIT_NOFILE, (_hard, _hard)); print("nofile", _hard)
which = set(sys.argv[1:]) or {"sessions", "loris", "unread", "term"}

def io_probe(h, n=50):
    """write+flush latency (max, mean) over n rounds"""
    ts = []
    for i in range(n):
        t = time.monotonic()
        h.pwrite(mk.pattern(4096 * (i % 64), 4096, 100 + i), 4096 * (i % 64))
        h.flush()
        ts.append(time.monotonic() - t)
    return max(ts), sum(ts) / len(ts)

def nb_connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        s.connect(path)
    except BlockingIOError:
        return s, "pending"
    except OSError as e:
        s.close()
        return None, f"err:{errno.errorcode.get(e.errno, e.errno)}"
    return s, "ok"

v = mk.Vol(tag="h2")
try:
    v.create(); v.start()
    pid = v.proc.pid
    h = mk.connect(v.sock)
    print("baseline io max/mean %.4f %.4f" % io_probe(h), "rss", ctl.rss_kb(pid), "fds", ctl.nfds(pid), "threads", ctl.nthreads(pid))

    if "sessions" in which:
        # 5000 connections that send nothing
        conns = []; res = {}
        t0 = time.monotonic()
        for i in range(5000):
            s, how = nb_connect(v.control)
            res[how] = res.get(how, 0) + 1
            if s: conns.append(s)
        print("5000 silent connects:", res, "in %.2fs" % (time.monotonic() - t0))
        time.sleep(1)
        print(" daemon rss", ctl.rss_kb(pid), "fds", ctl.nfds(pid), "threads", ctl.nthreads(pid))
        print(" io with sessions held max/mean %.4f %.4f" % io_probe(h))
        # a fresh well-behaved client now
        t = time.monotonic()
        try:
            st = ctl.status(v.control, timeout=8)
            print(" status while saturated: answered in %.2fs" % (time.monotonic() - t))
        except Exception as e:
            print(" status while saturated: %r after %.2fs" % (e, time.monotonic() - t))
        # the CLI's view
        r = subprocess.run([mk.MAKI, "status", "--socket", v.control, "--timeout", "5"], capture_output=True, text=True)
        print(" maki status --timeout 5 ->", r.returncode, r.stderr.strip()[:200])
        # how long until the first 64 are timed out and the next served?
        t = time.monotonic()
        try:
            st = ctl.status(v.control, timeout=200)
            print(" status answered after %.1fs of waiting behind idle sessions" % (time.monotonic() - t))
        except Exception as e:
            print(" status: %r after %.1fs" % (e, time.monotonic() - t))
        print(" daemon rss", ctl.rss_kb(pid), "fds", ctl.nfds(pid))
        for s in conns: s.close()
        time.sleep(1.0)
        t = time.monotonic()
        st = ctl.status(v.control, timeout=100)
        print(" after closing all: status in %.2fs, fds %d" % (time.monotonic() - t, ctl.nfds(pid)))

    if "loris" in which:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(v.control)
        t0 = time.monotonic(); closed = None
        s.setblocking(False)
        data = b'{"command":"status"' + b" " * 500
        i = 0
        while time.monotonic() - t0 < 150:
            try:
                s.send(data[i % len(data):i % len(data) + 1]); i += 1
            except (BrokenPipeError, ConnectionResetError):
                closed = time.monotonic() - t0; break
            r, _, _ = select.select([s], [], [], 5)
            if r:
                try:
                    d = s.recv(100)
                except ConnectionResetError:
                    d = b""
                if not d:
                    closed = time.monotonic() - t0; break
        print("slow loris (1 byte / 5 s): closed after", closed, "s; bytes sent", i)
        s.close()

    if "unread" in which:
        # a client that pipelines requests forever and never reads
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(v.control)
        s.setblocking(False)
        req = b'{"command":"metrics"}\n' * 2000
        sent = 0; t0 = time.monotonic(); closed = None
        rss0 = ctl.rss_kb(pid)
        while time.monotonic() - t0 < 40:
            try:
                sent += s.send(req)
            except BlockingIOError:
                select.select([], [s], [], 0.5)
            except (BrokenPipeError, ConnectionResetError):
                closed = time.monotonic() - t0; break
        print("unread pipeline: sent %d bytes, closed after %s s, rss before/after %d/%d" % (sent, closed, rss0, ctl.rss_kb(pid)))
        s.close()
        # 64 such clients at once, and I/O latency meanwhile
        socks = []
        for _ in range(64):
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); c.connect(v.control); c.setblocking(False); socks.append(c)
        stop = time.monotonic() + 12
        lat = []
        def pump():
            live = list(socks)
            while time.monotonic() < stop and live:
                for c in list(live):
                    try: c.send(req)
                    except BlockingIOError: pass
                    except OSError: live.remove(c)
                time.sleep(0.01)
        th = threading.Thread(target=pump); th.start()
        time.sleep(1)
        print(" io under 64 unread pipelines max/mean %.4f %.4f" % io_probe(h, 100), "rss", ctl.rss_kb(pid))
        th.join()
        for c in socks: c.close()
        time.sleep(0.5)
        print(" status after:", ctl.status(v.control)["state"], "rss", ctl.rss_kb(pid), "fds", ctl.nfds(pid))

    if "term" in which:
        # SIGTERM with: 64 idle sessions, a backlog, sessions mid-request, a half-sent line
        conns = []
        for i in range(300):
            s, how = nb_connect(v.control)
            if s: conns.append(s)
        for s in conns[:20]:
            try: s.send(b'{"command":"sta')
            except OSError: pass
        for s in conns[20:40]:
            try: s.send(b'{"command":"checkpoint"}\n' * 50)
            except OSError: pass
        h.pwrite(mk.pattern(0, 65536, 7), 0); h.flush()
        h.shutdown()
        t = time.monotonic()
        rc = v.term(timeout=60)
        print("SIGTERM with 300 hostile connections: rc", rc, "in %.2fs" % (time.monotonic() - t))
        # restart at once: the volume lock must be free, the control socket rebindable
        t = time.monotonic()
        v.start()
        print("restart ok in %.2fs; control socket inode replaced; status %s" % (time.monotonic() - t, ctl.status(v.control)["state"]))
        h = mk.connect(v.sock)
        assert h.pread(65536, 0) == mk.pattern(0, 65536, 7)
        for s in conns: s.close()
        h.shutdown()
        print("term rc", v.term())
    for i in range(1, v.n + 1):
        p = os.path.join(v.dir, f"nbdkit-{i}.log")
        for line in open(p, errors="replace"):
            print(f"LOG{i}:", line.rstrip()[:260])
finally:
    v.cleanup()
