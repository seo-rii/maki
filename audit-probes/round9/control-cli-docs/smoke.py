"""Smoke: create a volume, serve it under nbdkit, write+flush, read status/metrics."""
import sys, json, socket, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk

def ctl(path, obj, timeout=10):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    s.sendall((json.dumps(obj) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        d = s.recv(65536)
        if not d:
            break
        buf += d
    s.close()
    return json.loads(buf)

v = mk.Vol(tag="smoke")
try:
    print(v.create().stdout.strip())
    v.start()
    h = mk.connect(v.sock)
    print("size", h.get_size())
    h.pwrite(mk.pattern(0, 8192, 1), 0)
    h.flush()
    st = ctl(v.control, {"command": "status"})
    print(json.dumps(st, indent=1))
    me = ctl(v.control, {"command": "metrics"})
    print(json.dumps(me, indent=1))
    print(oct(os.stat(v.control).st_mode), os.stat(v.control).st_uid, os.stat(v.control).st_gid)
    h.shutdown()
    print("term rc", v.term())
    print(v.read_log()[-1500:])
finally:
    v.cleanup()
