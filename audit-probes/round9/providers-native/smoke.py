"""Baseline: each transport, plaintext loopback, real nbdkit + plugin.
Create, attach, write/read/flush, restart, read back, `maki status`."""
import sys, time, json, subprocess
import rp

only = sys.argv[1:] or ["http", "ws", "grpc"]
ok = True
for transport in only:
    beh = rp.Behaviour()
    srv = {"http": rp.HttpServer, "ws": rp.WsServer, "grpc": rp.GrpcServer}[transport](beh)
    v = rp.Vol(f"smoke-{transport}", transport, [srv.url()])
    try:
        r = v.create(check=False)
        print(transport, "create", r.returncode, r.stdout.strip()[-200:], r.stderr.strip()[-400:])
        v.start()
        h = rp.connect(v.sock)
        print(transport, "size", h.get_size(), "flush", h.can_flush(), "fua", h.can_fua())
        d = rp.pattern(0, 16384, 1)
        t = time.monotonic()
        h.pwrite(d, 0)
        h.flush()
        assert h.pread(16384, 0) == d
        import nbd
        h.pwrite(rp.pattern(65536, 4096, 2), 65536, nbd.CMD_FLAG_FUA)
        print(transport, "io ok in %.3fs" % (time.monotonic() - t), "calls", beh.calls, "items", beh.items)
        st = v.maki("status", v.cfg)
        print(transport, "status rc", st.returncode, st.stdout[:600].replace("\n", " "))
        h.shutdown()
        rc = v.term()
        print(transport, "term rc", rc)
        v.start()
        h = rp.connect(v.sock)
        assert h.pread(16384, 0) == d
        assert h.pread(4096, 65536) == rp.pattern(65536, 4096, 2)
        assert h.pread(4096, 32768) == bytes(4096)
        h.shutdown()
        print(transport, "restart readback ok; term", v.term())
        print(v.read_log(1)[-1200:])
    except Exception as e:
        ok = False
        print(transport, "FAILED", repr(e))
        print(v.read_log()[-3000:])
    finally:
        v.cleanup()
        srv.stop()
sys.exit(0 if ok else 1)
