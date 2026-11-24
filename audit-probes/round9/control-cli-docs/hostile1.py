"""Hostile control clients, part 1: wire decoder cases (one request per connection and pipelined)."""
import sys, os, json, time, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk, ctl

v = mk.Vol(tag="h1", cache='mode = "read"\nmax_bytes = "1MiB"\nttl = "30s"')
out = []
try:
    v.create(); v.start()
    pid = v.proc.pid
    h = mk.connect(v.sock)
    h.pwrite(mk.pattern(0, 65536, 1), 0); h.flush()
    cases = [
        ("empty line", b"\n"),
        ("spaces", b"   \n"),
        ("not json", b"hello\n"),
        ("array", b"[]\n"),
        ("string", b'"status"\n'),
        ("null", b"null\n"),
        ("no command", b"{}\n"),
        ("command int", b'{"command":1}\n'),
        ("command null", b'{"command":null}\n'),
        ("dup command", b'{"command":"status","command":"drain"}\n'),
        ("unknown field", b'{"command":"status","x":1}\n'),
        ("crlf", b'{"command":"status"}\r\n'),
        ("nul inside", b'{"command":"sta\x00tus"}\n'),
        ("nul escaped", b'{"command":"sta\\u0000tus"}\n'),
        ("invalid utf8", b'{"command":"\xff\xfe"}\n'),
        ("lone surrogate", b'{"command":"\\ud800"}\n'),
        ("deep nest payload", b'{"command":"reload","section":"cache","payload":' + b"[" * 5000 + b"]" * 5000 + b"}\n"),
        ("deep nest objects", b'{"command":"status","payload":' + b'{"a":' * 3000 + b"1" + b"}" * 3000 + b"}\n"),
        ("huge number", b'{"command":"reload","section":"cache","payload":{"max_bytes":1e400}}\n'),
        ("big int", b'{"command":"reload","section":"cache","payload":{"max_bytes":' + b"9" * 4000 + b"}}\n"),
        ("neg max", b'{"command":"reload","section":"cache","payload":{"max_bytes":-1}}\n'),
        ("float max", b'{"command":"reload","section":"cache","payload":{"max_bytes":4096.0}}\n'),
        ("max 0", b'{"command":"reload","section":"cache","payload":{"max_bytes":0}}\n'),
        ("max 1", b'{"command":"reload","section":"cache","payload":{"max_bytes":1}}\n'),
        ("max size", b'{"command":"reload","section":"cache","payload":{"max_bytes":4194304}}\n'),
        ("max size+1", b'{"command":"reload","section":"cache","payload":{"max_bytes":4194305}}\n'),
        ("max u64", b'{"command":"reload","section":"cache","payload":{"max_bytes":18446744073709551615}}\n'),
        ("ttl huge", b'{"command":"reload","section":"cache","payload":{"max_bytes":4096,"ttl":"18446744073709551615s"}}\n'),
        ("ttl overflow m", b'{"command":"reload","section":"cache","payload":{"max_bytes":4096,"ttl":"18446744073709551615m"}}\n'),
        ("ttl int", b'{"command":"reload","section":"cache","payload":{"max_bytes":4096,"ttl":5}}\n'),
        ("ttl zero", b'{"command":"reload","section":"cache","payload":{"max_bytes":4096,"ttl":"0s"}}\n'),
        ("ttl 1us", b'{"command":"reload","section":"cache","payload":{"max_bytes":4096,"ttl":"1us"}}\n'),
        ("ttl null", b'{"command":"reload","section":"cache","payload":{"max_bytes":4096,"ttl":null}}\n'),
        ("payload array", b'{"command":"reload","section":"cache","payload":[1]}\n'),
        ("payload null", b'{"command":"reload","section":"cache"}\n'),
        ("extra field", b'{"command":"reload","section":"cache","payload":{"max_bytes":4096,"mode":"off"}}\n'),
        ("section missing", b'{"command":"reload"}\n'),
        ("section int", b'{"command":"reload","section":5}\n'),
        ("section long", b'{"command":"reload","section":"' + b"A" * 60000 + b'"}\n'),
        ("section esc long", b'{"command":"reload","section":"' + b"\\u0001" * 10000 + b'"}\n'),
        ("cmd long", b'{"command":"' + b"B" * 60000 + b'"}\n'),
        ("cmd esc long", b'{"command":"' + b"\\\"" * 30000 + b'"}\n'),
        ("privileged attach", b'{"command":"attach"}\n'),
        ("privileged lvm", b'{"command":"lvm"}\n'),
        ("case STATUS", b'{"command":"STATUS"}\n'),
        ("shutdown verb", b'{"command":"shutdown"}\n'),
        ("create verb", b'{"command":"volume create"}\n'),
        ("exact 64k line", b'{"command":"status","x":"' + b"a" * (65536 - 28) + b'"}\n'),
        ("64k+1 line", b'{"command":"status","x":"' + b"a" * (65536 - 27) + b'"}\n'),
        ("1MiB no newline", b"a" * (1 << 20)),
        ("eof-terminated object", None),
        ("truncated json eof", None),
    ]
    for name, data in cases:
        t = time.monotonic()
        if name == "eof-terminated object":
            buf, how = ctl.raw(v.control, b'{"command":"status"}', shut=True)
        elif name == "truncated json eof":
            buf, how = ctl.raw(v.control, b'{"command":"sta', shut=True)
        else:
            try:
                buf, how = ctl.raw(v.control, data, timeout=15)
            except OSError as e:
                buf, how = b"", f"send-err:{e.errno}"
        dt = time.monotonic() - t
        if name in ("exact 64k line",):
            print(f"{name:24} len={len(data)} -> {how} {dt:.2f}s {len(buf)}B {buf[:60]!r}")
        else:
            print(f"{name:24} -> {how} {dt:.2f}s {len(buf)}B {buf[:230]!r}")
    # the daemon still serves
    print("status after:", ctl.status(v.control)["state"], "rss_kb", ctl.rss_kb(pid), "fds", ctl.nfds(pid))
    assert h.pread(65536, 0) == mk.pattern(0, 65536, 1)
    # pipelined mix on one connection: every request answered in order
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10); s.connect(v.control)
    s.sendall(b'{"command":"status"}\n{bad\n{"command":"metrics"}\n\n{"command":"checkpoint"}\n')
    buf = b""
    while buf.count(b"\n") < 5:
        d = s.recv(65536)
        if not d: break
        buf += d
    for line in buf.split(b"\n")[:5]:
        print("pipelined:", line[:90])
    s.close()
    h.shutdown()
    print("term rc", v.term())
    log = v.read_log()
    print("log lines:", len(log.splitlines()))
    for line in log.splitlines():
        if "control" in line or "panic" in line.lower():
            print("LOG:", line[:300])
finally:
    v.cleanup()
