#!/usr/bin/python3.12
"""Runtime-tunable settings changed between a kill -9 and the restart, with an
uncheckpointed journal on disk: the volume must attach with every
acknowledged-durable byte, or refuse cleanly and attach again with the old
settings."""
import sys, os, re, random, nbd, mk
fails = 0
def note(ok, what, detail=""):
    global fails
    print(("PASS " if ok else "FAIL ") + what + (" :: " + str(detail)[-500:] if detail else ""), flush=True)
    fails += 0 if ok else 1

def fill(v, rng, n=90):
    h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
    size = h.get_size(); model = bytearray(h.pread(size, 0))
    for i in range(n):
        ln = rng.choice([512, 4096, 16384, 65536, 65536 * 2 + 512])
        off = rng.randrange(0, (size - ln) // 512) * 512
        d = mk.pattern(off, ln, rng.randrange(1, 1 << 40)); h.pwrite(d, off); model[off:off + ln] = d
    h.flush()
    return h, model

def check(v, model, what):
    h = nbd.NBD()
    for _ in range(200):
        try:
            h.connect_unix(v.sock); break
        except nbd.Error:
            import time; time.sleep(0.02); h = nbd.NBD()
    got = bytes(h.pread(len(model), 0))
    note(got == bytes(model), what)
    return h

CASES = [
    ("smaller segments and journal limit", dict(seg="16KiB", jmax="256KiB", max_io="16KiB")),
    ("smaller maximum_io", dict(max_io="16KiB")),
    ("larger maximum_io and journal", dict(max_io="1MiB", jmax="4MiB", seg="1MiB")),
    ("tight overlay and pending limits", dict(extra_limits='max_overlay_bytes = "160KiB"\nmax_overlay_entries = 17\nmax_journal_pending_bytes = "4KiB"\nmax_plaintext_bytes = "128KiB"\nmax_active_callbacks = 1')),
    ("read cache switched on", dict(cache='mode = "read"\nmax_bytes = "32KiB"\nttl = "1s"\nverify_on_hit = true')),
    ("emergency reserve switched on", dict(reserve="64KiB", ckpt_reserve="128KiB")),
    ("nbd threads 1", dict(extra_nbd="threads = 1")),
]
rng = random.Random(8)
for discard in (False, True):
    for name, change in CASES:
        tag = f"{'v3' if discard else 'v2'} {name}"
        v = mk.Vol("drift", discard=discard, jmax="1MiB")
        try:
            v.create(); v.start()
            h, model = fill(v, rng)
            # a little more, unflushed but acknowledged before a clean... no: kill -9
            v.kill9()
            base_cfg = dict(jmax="1MiB"); new_cfg = dict(base_cfg); new_cfg.update(change)
            old_text = v.text
            v.text = mk.config_text(v.root, v.control, key_path=v.key, **new_cfg)
            open(v.cfg, "w").write(v.text)
            try:
                v.start()
            except RuntimeError as e:
                msg = str(e)
                note("panic" not in msg.lower(), f"{tag}: refused cleanly", msg.strip().splitlines()[-1])
                open(v.cfg, "w").write(old_text); v.text = old_text
                v.start()
                check(v, model, f"{tag}: after the refusal the old settings attach with all data").shutdown()
                continue
            h = check(v, model, f"{tag}: attaches with all flushed data")
            h.shutdown()
            # work under the new settings, clean stop, back to the old settings
            h, model = fill(v, rng, 40)
            h.shutdown()
            rc = v.term(60)
            note(rc == 0, f"{tag}: clean stop under the new settings", rc)
            open(v.cfg, "w").write(old_text); v.text = old_text
            try:
                v.start()
                check(v, model, f"{tag}: old settings attach again with all data").shutdown()
            except RuntimeError as e:
                note(False, f"{tag}: old settings attach again", str(e)[-400:])
            log = v.all_logs()
            note("panic" not in log.lower(), f"{tag}: no panic")
        finally:
            v.cleanup()
print(f"{fails} FAIL(s)"); sys.exit(1 if fails else 0)
