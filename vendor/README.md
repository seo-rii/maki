# Pinned plaintext-erasure patches

Maki uses local patches of `serde_json` 1.0.151 and `rustls` 0.23.45. Their
published sources and licenses are retained here. `upstream.json` records the
published crate archive SHA-256 and every original file hash; the archive hashes
were checked against the pre-patch workspace lockfile. These patches change
buffer ownership, not the TLS wire protocol or JSON syntax.

`serde_json` erases its private string/number scratch before reuse and its full
allocation before growth or release. Integer128 scanning and error-message
formatting use the same ownership. Parsed values, borrowed input and messages
formatted by callers remain caller-owned. A caller-retained `Deserializer`
keeps its latest scratch until reuse or Drop; a visitor may still borrow it.
The `raw_value`, `arbitrary_precision`
and `float_roundtrip` feature paths are refused at compile time because their
additional raw-value and lexical owners have not been covered by this patch.

`rustls` erases consumed plaintext queues and deframer regions, including
obsolete compaction tails. Replacing or releasing these buffers erases their
full capacity. Inbound payload guards erase data on errors and erase excluded
ranges on truncation; encryption staging is guarded through errors and growth.
Successful API transfers retain the receiving caller's ownership.

The test-only `maki-test-allocator` observes initialized live allocations just
before release. It initializes spare capacity so observation is defined, stores
watch metadata in fixed thread-local records, and never reads freed memory.
It is not used as a production allocator. `test-ca` contains public upstream
test certificates and keys, with additional `rustls/src/testdata`, message
corpus and RFC 9180 fixtures,
from the exact rustls source commit recorded in
`test-ca-provenance.json`; these are fixtures, not deployed credentials.

The ownership guarantee covers these libraries' application-data heap buffers.
Stack/register copies made by parsing or cryptographic code, caller-owned
buffers, kernel buffers and other transport libraries' live framing allocations
are separate owners. Process termination that skips destructors cannot provide
normal Drop cleanup. Page locking and total memory bounds remain separate.

To update either library, start from the new published archive, verify its
checksum, reapply and review each ownership change, and rerun the erasure
regressions and protocol tests before changing the pinned version. Inspect new
features and new allocation/clear/consume/shrink paths; an unchanged public API
does not prove the same internal lifetimes. Update the upstream inventory and
patch manifest together. CI runs the dependency contract and the explicit vendor
tests because these packages are excluded from workspace membership.
