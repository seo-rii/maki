"""Control-socket client helpers for the round-9 control-cli-docs probes."""
import json, socket, time, os

def raw(path, data, timeout=10, shut=False, read=True):
    """Send bytes, return everything received until EOF/timeout (bytes) and how the read ended."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    if data:
        s.sendall(data)
    if shut:
        s.shutdown(socket.SHUT_WR)
    buf = b""
    how = "open"
    if read:
        try:
            while True:
                d = s.recv(1 << 16)
                if not d:
                    how = "eof"
                    break
                buf += d
                if buf.endswith(b"\n") and not shut:
                    how = "line"
                    break
        except socket.timeout:
            how = "timeout"
        except OSError as e:
            how = f"err:{e.errno}"
    s.close()
    return buf, how

def call(path, obj, timeout=30):
    buf, how = raw(path, (json.dumps(obj) + "\n").encode(), timeout=timeout)
    if how != "line":
        raise RuntimeError(f"control call ended {how}: {buf[:200]!r}")
    return json.loads(buf)

def status(path, timeout=30):
    return call(path, {"command": "status"}, timeout)["data"]

def metrics(path, timeout=30):
    return call(path, {"command": "metrics"}, timeout)["data"]

def rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return -1

def nfds(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))

def nthreads(pid):
    return len(os.listdir(f"/proc/{pid}/task"))
