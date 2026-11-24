import nbd, mk, time, select
v = mk.Vol("aio")
try:
    v.create(); v.start()
    h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
    done = []
    def cb(tag):
        def f(err):
            done.append((tag, err.value if hasattr(err, "value") else err)); return 1
        return f
    t = time.time()
    n = 200
    for i in range(n):
        c = h.aio_pwrite(mk.pattern(i*4096, 4096, 1), i*4096, cb(i), 0)
    while len(done) < n:
        h.poll(1000)
    print("200 unit writes, all in flight at once:", time.time() - t, "s; in_flight", h.aio_in_flight())
    t = time.time()
    for i in range(50):
        h.pwrite(mk.pattern(i*4096, 4096, 2), i*4096, nbd.CMD_FLAG_FUA)
    print("50 sequential FUA writes:", time.time() - t)
    t = time.time(); h.flush(); print("flush", time.time() - t)
    buf = nbd.Buffer(4096)
    r = []
    h.aio_pread(buf, 0, lambda e: r.append(e.value) or 1)
    while not r: h.poll(1000)
    print("aio_pread err", r, buf.to_bytearray()[:8].hex())
    # bad request error value
    r = []
    h.aio_pwrite(b"x"*100, 7, lambda e: r.append(e.value) or 1, 0)
    while not r: h.poll(1000)
    print("aio bad write err", r)
    print(v.maki("metrics", v.cfg).stdout[:3000])
finally:
    v.cleanup()
