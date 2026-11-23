"""Second probe set: which byte-valued keys accept suffixed sizes."""
import pathlib, copy, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from mkcases import ser, base, here
out = here / 'cases2'; out.mkdir(exist_ok=True)
for old in out.glob('*.toml'): old.unlink()
def setp(path, value):
    def f(cfg):
        cur = cfg
        for k in path[:-1]: cur = cur.setdefault(k, {})
        cur[path[-1]] = value
    return f
P = [
 ('expect-fail-suffix-nbd-minimum_io', ['nbd', 'minimum_io'], '4KiB'),
 ('expect-fail-suffix-nbd-preferred_io', ['nbd', 'preferred_io'], '4KiB'),
 ('suffix-nbd-maximum_io', ['nbd', 'maximum_io'], '1MiB'),
 ('expect-fail-suffix-nbd-device_block_size', ['nbd', 'device_block_size'], '4KiB'),
 ('expect-fail-suffix-volume-device_block_size', ['volume', 'device_block_size'], '4KiB'),
 ('expect-fail-suffix-volume-crypto_unit_size', ['volume', 'crypto_unit_size'], '4KiB'),
 ('suffix-volume-shard_logical_size', ['volume', 'shard_logical_size'], '1GiB'),
 ('expect-fail-suffix-backing-slot_alignment', ['backing', 'slot_alignment'], '4KiB'),
 ('expect-fail-suffix-capabilities-max_ciphertext_size', ['crypto', 'capabilities', 'max_ciphertext_size'], '4384B'),
 ('expect-fail-suffix-crypto-random_prefix_bytes', ['crypto', 'random_prefix_bytes'], '0B'),
 ('suffix-B-accepted', ['cache', 'max_bytes'], '4096B'),
 ('expect-fail-suffix-KB', ['cache', 'max_bytes'], '4KB'),
 ('expect-fail-suffix-lowercase-kib', ['cache', 'max_bytes'], '4kib'),
 ('suffix-space-before-unit', ['cache', 'max_bytes'], '4 KiB'),
 ('expect-fail-float-size', ['cache', 'max_bytes'], 1.5),
 ('rate-number', ['crypto', 'retry_budget', 'minimum_probe_rate'], 2),
 ('rate-string', ['crypto', 'retry_budget', 'minimum_probe_rate'], '0.5/s'),
 ('expect-fail-rate-per-minute', ['crypto', 'retry_budget', 'minimum_probe_rate'], '1/m'),
 ('duration-us', ['crypto', 'batch', 'max_wait'], '150us'),
 ('expect-fail-duration-ns', ['crypto', 'batch', 'max_wait'], '150ns'),
 ('expect-fail-duration-fraction', ['crypto', 'batch', 'max_wait'], '1.5ms'),
]
for name, path, value in P:
    cfg = copy.deepcopy(base); setp(path, value)(cfg)
    (out / (name + '.toml')).write_text(ser(cfg) + '\n')
print(len(P))
