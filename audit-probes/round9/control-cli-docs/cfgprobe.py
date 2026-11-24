"""Configuration as the tools read it.
Part 1: one changed setting between `volume create` and attach (plugin under nbdkit), plus the
offline tools and maki-benchmark with the changed file.  Part 2: values at and beyond bounds,
unknown/duplicate keys, odd paths, literal secrets: classified by `maki volume inspect` (it parses
and validates before it looks at the backing)."""
import sys, os, re, subprocess, shutil, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk
BENCH = os.path.join(os.path.dirname(mk.MAKI), "maki-benchmark")
SECRET = "S3CR3T-do-not-print-0123456789abcdef"
which = set(sys.argv[1:]) or {"change", "bounds"}

def run(*args, env=None, timeout=60):
    e = dict(os.environ); e.update(env or {})
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=e)
    return r.returncode, (r.stdout + r.stderr).strip()

def attach(v, text):
    open(v.cfg, "w").write(text)
    try:
        v.start(timeout=30)
    except RuntimeError as e:
        try: v.notify.close()
        except Exception: pass
        m = re.search(r"before READY: (.*)", str(e), re.S)
        return False, (m.group(1) if m else str(e)).strip().replace("\n", " | ")[-420:]
    import nbd
    h = mk.connect(v.sock); size = h.get_size(); h.shutdown(); v.term()
    return True, f"READY size={size}"

if "change" in which:
    print("== one setting changed between create and attach ==")
    v = mk.Vol(tag="cfgchg", size="4MiB")
    key2 = os.path.join(v.dir, "other.key"); open(key2, "w").write(mk.KEY_HEX); os.chmod(key2, 0o600)
    key3 = os.path.join(v.dir, "wrong.key"); open(key3, "w").write("ff" * 32); os.chmod(key3, 0o600)
    try:
        base = v.text
        v.create(); ok, msg = attach(v, base); print("baseline:", ok, msg)
        gold = v.root + ".gold"; shutil.copytree(v.root, gold)
        def sub(a, b, text=base):
            assert a in text, a
            return text.replace(a, b)
        changes = [
            ("volume.max_virtual_size 4MiB->8MiB", sub('max_virtual_size = "4MiB"', 'max_virtual_size = "8MiB"'), "max_virtual_size"),
            ("volume.max_virtual_size 4MiB->2MiB", sub('max_virtual_size = "4MiB"', 'max_virtual_size = "2MiB"'), "max_virtual_size"),
            ("volume.device_block_size 512->4096", sub("device_block_size = 512", "device_block_size = 4096").replace("minimum_io = 512", "minimum_io = 4096"), "device_block_size"),
            ("volume.crypto_unit_size 4096->8192", sub("crypto_unit_size = 4096", "crypto_unit_size = 8192").replace("supported_plaintext_sizes = [4096]", "supported_plaintext_sizes = [8192]").replace("max_ciphertext_size = 4160", "max_ciphertext_size = 8256"), "crypto_unit_size"),
            ("volume.shard_logical_size 64KiB->128KiB", sub('shard_logical_size = "64KiB"', 'shard_logical_size = "128KiB"'), "shard_logical_size"),
            ("backing.slot_alignment 512->4096", sub("[backing]\n", "[backing]\nslot_alignment = 4096\n"), "slot_alignment"),
            ("capabilities.max_ciphertext_size 4160->4200", sub("max_ciphertext_size = 4160", "max_ciphertext_size = 4200"), "max_ciphertext_size"),
            ("crypto.provider gcm-siv->xts", sub('provider = "local-aes-gcm-siv"', 'provider = "local-aes-xts"'), "provider"),
            ("crypto.crypto_compatibility_id", sub('crypto_compatibility_id = "local-profile-v1"', 'crypto_compatibility_id = "local-profile-v2"'), "compatib"),
            ("crypto.key name (same key bytes, other path)", sub(v.key, key2), "key"),
            ("crypto.key content (other key, same path semantics)", sub(v.key, key3), "key"),
            ("crypto.key source file->env (same name)", sub('source = "file"', 'source = "env"'), "key"),
            ("crypto.random_prefix_bytes 0->16", sub("[crypto]\n", "[crypto]\nrandom_prefix_bytes = 16\n").replace("supported_plaintext_sizes = [4096]", "supported_plaintext_sizes = [4112]"), "prefix"),
            ("nbd.minimum_io 512->4096 (allowed: size is a multiple)", sub("minimum_io = 512", "minimum_io = 4096"), None),
            ("backing.journal_segment_size 64KiB->128KiB (documented as changeable)", sub('journal_segment_size = "64KiB"', 'journal_segment_size = "128KiB"'), None),
            ("backing.journal_segment_size 64KiB->4096 (lowered)", sub('journal_segment_size = "64KiB"', 'journal_segment_size = "4096"').replace('journal_max_bytes = "512KiB"', 'journal_max_bytes = "2MiB"'), None),
            ("volume.name renamed", sub('name = "a9cvol"', 'name = "renamed"'), None),
            ("rollback section added to a plain volume", sub("[limits]", f'[backing.rollback_protection]\nwitness_root = "{v.dir}/witness"\ncapacity = "64MiB"\n[limits]').replace('journal_emergency_reserve_bytes = "0B"', 'journal_emergency_reserve_bytes = "0B"\ncheckpoint_reserve_bytes = "0B"'), "rollback"),
        ]
        for name, text, must_name in changes:
            shutil.rmtree(v.root); shutil.copytree(gold, v.root)
            ok, msg = attach(v, text)
            flag = ""
            if must_name and ok: flag = "  <-- ACCEPTED"
            elif must_name and must_name.lower() not in msg.lower(): flag = f"  <-- message does not name {must_name!r}"
            if mk.KEY_HEX in msg or ("ff" * 32) in msg: flag += "  <-- KEY IN MESSAGE"
            print(f"- {name}: {'attached' if ok else 'refused'}: {msg[-330:]}{flag}")
            rc, out = run(mk.MAKI, "check", v.cfg, "--deep"); c = out.splitlines()[-1] if out else ""
            rc2, out2 = run(BENCH, "--destroy-data", v.cfg, "8", "4096")
            print(f"    check --deep rc={rc} ({c[:90]}); maki-benchmark --destroy-data rc={rc2}: {out2.splitlines()[-1][:230] if out2 else ''}")
        # protected volume: capacity / witness changes
        shutil.rmtree(v.root)
        prot = sub("[limits]", f'[backing.rollback_protection]\nwitness_root = "/dev/shm/a9c-wit-{os.getpid()}"\ncapacity = "64MiB"\n[limits]').replace('journal_emergency_reserve_bytes = "0B"', 'journal_emergency_reserve_bytes = "0B"\ncheckpoint_reserve_bytes = "0B"')
        open(v.cfg, "w").write(prot)
        rc, out = run(mk.MAKI, "volume", "create", v.cfg); print("protected create:", rc, out[-200:])
        if rc == 0:
            ok, msg = attach(v, prot); print("protected baseline:", ok, msg[-200:])
            for name, text, must in [
                ("rollback capacity 64MiB->128MiB", prot.replace('capacity = "64MiB"', 'capacity = "128MiB"'), "capacity"),
                ("rollback capacity 64MiB->32MiB", prot.replace('capacity = "64MiB"', 'capacity = "32MiB"'), "capacity"),
                ("rollback section removed", base, "rollback"),
                ("witness_root moved to an empty directory", prot.replace(f"a9c-wit-{os.getpid()}", f"a9c-wit2-{os.getpid()}"), "witness"),
            ]:
                ok, msg = attach(v, text)
                flag = "  <-- ACCEPTED" if ok else ("" if must in msg.lower() else f"  <-- message does not name {must!r}")
                print(f"- {name}: {'attached' if ok else 'refused'}: {msg[-330:]}{flag}")
                rc, out = run(mk.MAKI, "check", v.cfg); print(f"    check rc={rc}: {out.splitlines()[-1][:200] if out else ''}")
                rc, out = run(mk.MAKI, "volume", "inspect", v.cfg); print(f"    inspect rc={rc}: {out.splitlines()[-1][:200] if out else ''}")
    finally:
        v.cleanup()
        for d in (f"/dev/shm/a9c-wit-{os.getpid()}", f"/dev/shm/a9c-wit2-{os.getpid()}"): shutil.rmtree(d, ignore_errors=True)

if "bounds" in which:
    print("== bounds, unknown keys, odd values (classified by `maki volume inspect`) ==")
    v = mk.Vol(tag="cfgb", size="4MiB")
    try:
        base = v.text
        def case(name, text, raw=None):
            if raw is not None:
                open(v.cfg, "wb").write(raw)
            else:
                open(v.cfg, "w").write(text)
            rc, out = run(mk.MAKI, "volume", "inspect", v.cfg)
            verdict = "ACCEPTED" if "No such file or directory" in out and "volume" in out else "refused"
            flag = ""
            if SECRET in out or mk.KEY_HEX in out: flag = "  <-- SECRET ECHOED"
            if rc not in (1, 2) or "panicked" in out: flag += f"  <-- rc={rc}"
            print(f"- {name}: {verdict}: {out[-240:]!r}{flag}")
        def sub(a, b):
            assert a in base, a
            return base.replace(a, b)
        case("baseline", base)
        case("unknown top-level key", base + '\nsurprise = 1\n')
        case("unknown key in [volume]", sub("[volume]\n", "[volume]\nnmae = \"x\"\n"))
        case("unknown key carrying a secret", sub("[crypto]\n", f"[crypto]\ntoken = \"{SECRET}\"\n"))
        case("duplicate [volume] table", base + '\n[volume]\nname = "again"\n')
        case("duplicate key", sub('name = "a9cvol"', 'name = "a9cvol"\nname = "b"'))
        case("literal key string", sub('key = { source = "file", name = "%s" }' % v.key, f'key = "{SECRET}"'))
        case("key source literal", sub('source = "file"', 'source = "literal"').replace(v.key, SECRET))
        case("key source keyring", sub('source = "file"', 'source = "keyring"'))
        case("key file relative", sub(v.key, "relative.key"))
        case("key file name with space", sub(v.key, "/tmp/a b.key"))
        case("key env name with =", sub('source = "file"', 'source = "env"').replace(v.key, f"A={SECRET}"))
        case("key with format", sub(f'name = "{v.key}"', f'name = "{v.key}", format = "{SECRET}{{}}"'))
        for n in (64, 65): case(f"volume.name {n} bytes", sub('name = "a9cvol"', f'name = "{"n" * n}"'))
        case("volume.name with slash", sub('name = "a9cvol"', 'name = "a/b"'))
        case("volume.name non-ASCII", sub('name = "a9cvol"', 'name = "volé"'))
        case("volume.name leading dash", sub('name = "a9cvol"', 'name = "-x"'))
        for val in ('"0"', '"511B"', '"512B"', '"16777216TiB"', '"16777215TiB"', '-4096', '"4 MiB"', '"4mib"', '4194304.0', '"0x400000"'):
            case(f"max_virtual_size = {val}", sub('max_virtual_size = "4MiB"', f"max_virtual_size = {val}"))
        for val in (0, 256, 511, 1024, 2048, 4096, 8192, 65536):
            case(f"device_block_size = {val}", sub("device_block_size = 512", f"device_block_size = {val}").replace("minimum_io = 512", f"minimum_io = {max(val, 512)}"))
        for val in (0, 512, 1024, 3072, 4097, 16777216, 16777217, 33554432, 4294967295):
            case(f"crypto_unit_size = {val}", sub("crypto_unit_size = 4096", f"crypto_unit_size = {val}").replace("supported_plaintext_sizes = [4096]", f"supported_plaintext_sizes = [{val}]").replace("max_ciphertext_size = 4160", f"max_ciphertext_size = {min(val + 64, 4294967295)}").replace('maximum_io = "64KiB"', 'maximum_io = "64MiB"'))
        for val in ('"0"', '"4096"', '"4KiB"', '"1MiB"', '"3MiB"', '"64GiB"', '"16777216TiB"'):
            case(f"shard_logical_size = {val}", sub('shard_logical_size = "64KiB"', f"shard_logical_size = {val}"))
        for val in ('"4095"', '"4096"', '"1GiB"', '"1073741825"'):
            case(f"journal_segment_size = {val}", sub('journal_segment_size = "64KiB"', f"journal_segment_size = {val}").replace('journal_max_bytes = "512KiB"', 'journal_max_bytes = "4GiB"'))
        for val in ('"64KiB"', '"127KiB"', '"128KiB"', '"18446744073709551615"', '"18446744073709551616"'):
            case(f"journal_max_bytes = {val}", sub('journal_max_bytes = "512KiB"', f"journal_max_bytes = {val}"))
        for val in (0, 1, 256, 257, 4294967295, 4294967296, -1):
            case(f"nbd.threads = {val}", sub("[nbd]\n", f"[nbd]\nthreads = {val}\n"))
        for val in (0, 2):
            case(f"nbd.connections = {val}", sub("[nbd]\n", f"[nbd]\nconnections = {val}\n"))
        for val in (511, 1024, 65536, 131072):
            case(f"nbd.minimum_io = {val}", sub("minimum_io = 512", f"minimum_io = {val}").replace('maximum_io = "64KiB"', 'maximum_io = "1MiB"'))
        for val in ('"4096"', '"32MiB"', '"64MiB"', '"4GiB"', '"2GiB"'):
            case(f"nbd.maximum_io = {val}", sub('maximum_io = "64KiB"', f"maximum_io = {val}"))
        for val in (0, 4294967295):
            case(f"limits.max_active_callbacks = {val}", sub("[limits]\n", f"[limits]\nmax_active_callbacks = {val}\n"))
        for val in ('"0"', '"4096"', '"8191"', '"2GiB"'):
            case(f"limits.max_plaintext_bytes = {val}", sub("[limits]\n", f"[limits]\nmax_plaintext_bytes = {val}\n"))
        for val in ('"0s"', '"1us"', '"18446744073709551615m"', '"5"', '5', '"5 s"', '"1h"'):
            case(f"cache.ttl = {val}", sub("[limits]\n", f'[cache]\nmode = "read"\nttl = {val}\n[limits]\n'))
        for val in ('""', '"relative.sock"', '"/tmp/x/"', '"/tmp/x/.."', '"/' + "s" * 120 + '"', f'"{v.root}/superblock.a"', f'"{v.root}/journal/x.sock"', f'"{v.root}"', f'"{v.sock}"'):
            case(f"control.socket = {val[:60]}", sub(f'socket = "{v.control}"', f"socket = {val}"))
        for val in ('""', '" "', '"no-such-group-xyz"'):
            case(f"control.group = {val}", sub("[control]\n", f"[control]\ngroup = {val}\n"))
        for val in ('"relative/root"', '""', '"/tmp/a9c/has space"', '"/tmp/a9c/new\\nline"', '"/tmp/a9c/../a9c/dotdot"', '"/"'):
            case(f"backing.root = {val}", sub(f'root = "{v.root}"', f"root = {val}"))
        case("backing.root invalid UTF-8", None, raw=base.replace(f'root = "{v.root}"', 'root = "/tmp/a9c/\udcff"').encode("utf-8", "surrogateescape"))
        case("NUL byte in file", None, raw=base.encode() + b"\x00")
        case("config_schema_version = 2", sub("config_schema_version = 1", "config_schema_version = 2"))
        case("config_schema_version missing", sub("config_schema_version = 1", ""))
        case("empty file", "")
        case("memory_lock_mode = \"everything\"", base + '\n[security]\nmemory_lock_mode = "everything"\n')
        case("provider = \"fake\"", sub('provider = "local-aes-gcm-siv"', 'provider = "fake"').replace('key = { source = "file", name = "%s" }' % v.key, ""))
        case("provider = \"remote-http\" with literal Authorization", sub('provider = "local-aes-gcm-siv"', 'provider = "remote-http"').replace('key = { source = "file", name = "%s" }' % v.key, "") + f'\n[[crypto.http.endpoint]]\nname = "a"\nurl = "https://user:{SECRET}@example.test/x?k={SECRET}"\n[crypto.http.encrypt]\npath = "/e"\nheaders = {{ Authorization = "Bearer {SECRET}" }}\n[crypto.http.decrypt]\npath = "/d"\n')
        case("remote-http literal Authorization, clean url", sub('provider = "local-aes-gcm-siv"', 'provider = "remote-http"').replace('key = { source = "file", name = "%s" }' % v.key, "") + f'\n[[crypto.http.endpoint]]\nname = "a"\nurl = "https://example.test/x"\n[crypto.http.encrypt]\npath = "/e"\nheaders = {{ Authorization = "Bearer {SECRET}" }}\n[crypto.http.decrypt]\npath = "/d"\n')
        case("remote-http secret in X-Custom literal (not sensitive name)", sub('provider = "local-aes-gcm-siv"', 'provider = "remote-http"').replace('key = { source = "file", name = "%s" }' % v.key, "") + f'\n[[crypto.http.endpoint]]\nname = "a"\nurl = "http://203.0.113.9/x"\n[crypto.http.encrypt]\npath = "/e?t={SECRET}"\n[crypto.http.decrypt]\npath = "/d"\n')
    finally:
        v.cleanup()
