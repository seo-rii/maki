# Random plaintext prefixes

`crypto.random_prefix_bytes` optionally prepends fresh random bytes to every
plaintext crypto unit before passing it to the configured provider. It defaults
to `0` (disabled). Enabled lengths are 16 through 256 bytes, in multiples of 16.
The prefix is part of the encrypted plaintext, not a field appended to the
finished ciphertext and not the provider's nonce/IV.

```text
write: logical unit → random prefix || logical unit → provider encryption
read:  provider decryption → check full response → remove prefix
```

Existing nonce generation, authentication and context binding remain the
provider's responsibility. When the provider authenticates ciphertext, that
authentication covers the encrypted prefix too. The wrapper preserves its
security capability levels. The prefix is not evidence of integrity, context
binding or rollback protection. Its effect on repeated data depends on the provider's encryption
mode: random bytes in one plaintext block do not necessarily affect other
ciphertext blocks. Prefixes must not replace required IV/nonce handling. The
separate [rollback backing](rollback-protection.md) retains its own trust boundary.

## Configuration and lengths

For a local GCM-SIV provider with 4096-byte logical units, these fields enable a
32-byte prefix; merge them into an otherwise complete volume configuration:

```toml
[volume]
crypto_unit_size = 4096

[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-gcm-siv-v1"
random_prefix_bytes = 32
# Retain the existing key credential reference.

[crypto.capabilities]
supported_plaintext_sizes = [4128]
max_ciphertext_size = 4156
integrity = "verified"
context_binding = "verified"
replay_protection = "none"
```

The exported logical unit remains 4096 bytes. The provider accepts 4128 bytes,
and GCM-SIV produces 4156 bytes including its existing 12-byte nonce and 16-byte
tag. The slot alignment and slot header may reserve additional storage.
`max_ciphertext_size` always bounds the complete provider result; it is not
automatically increased by the prefix option. For other providers, use their
actual bound for the expanded plaintext size. Configuration and runtime
capability checks refuse unsupported sizes or insufficient bounds.

HTTP, WebSocket and gRPC providers must accept the expanded plaintext and return
it in full when decrypting. No new provider-side nonce field is required. The
configured base compatibility ID is still sent to the provider. A vendor with a
fixed 4096-byte input contract cannot serve the example without a profile that
accepts 4128 bytes.

Batch limits include the expanded provider plaintext. Consequently a batch may
hold fewer logical units than it did without the prefix. Remote dispatch and
its retry/admission controls receive the expanded bytes. Retries within one
dispatch operation reuse the same prepared plaintext; a new encryption call
generates fresh prefixes. Temporary plaintext uses the existing guarded,
zeroizing buffers.

The encrypt queue's `limits.max_pending_crypto_bytes` also reserves the expanded
size of each queued unit, rounding down to complete units. Prefixes are generated
after dequeue; pending-byte metrics still report the logical bytes currently
held in the queue. This is queue admission accounting, not a whole-process RSS
bound.

## Existing volumes and endpoint compatibility

Enabled volumes store a derived compatibility ID:

```text
maki-random-prefix-v1:<prefix bytes>:<configured base compatibility ID>
```

Do not put this derived value in the configuration. The
`maki-random-prefix-v1:` namespace is reserved for generated IDs. The full
derived value must fit the superblock's compatibility field.

Changing the prefix length or enabling/disabling the option on an existing
volume is refused, even if slot sizes happen to remain the same. To change the
setting, create a new volume with the desired configuration and copy data
through the normal plaintext interface or restore a logical backup. There is
no automatic in-place conversion. With the option omitted or zero, the original
compatibility ID and plaintext layout remain unchanged.

Remote endpoint self-tests, key-canary checks and cross-endpoint validation
exercise the wrapper under the actual volume context. Every endpoint must be
able to decrypt the same complete provider ciphertext, including the encrypted
prefix. Provider errors and malformed batch results are rejected before prefix
removal can expose logical plaintext. An encryption response identical to the
expanded input is also refused: the added prefix must not hide an endpoint
that simply returns the supplied plaintext.

## Focused validation

```sh
cargo test -p maki-crypto --test random_prefix
cargo test -p maki-format --test random_prefix_config
cargo test -p maki-nbdkit --test random_prefix --test random_prefix_remote --test random_prefix_admission
```

The suites inspect expanded provider inputs, independent prefix generation,
round trips, response shape and length errors, compatibility changes, logical
geometry, batch bounds, authenticated-prefix corruption, partial writes,
discard, reopen and rejection of unchanged provider plaintext. A two-endpoint
local reference service exercises the remote
daemon path. These tests validate the wrapper's behavior; they do not prove
additional cryptographic strength for an arbitrary vendor algorithm.
