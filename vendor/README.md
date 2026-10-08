# Pinned plaintext-erasure patches

Maki uses local patches of `serde_json` 1.0.151, `rustls` 0.23.45, `bytes`
1.12.1, `hyper` 1.11.1 and `tungstenite` 0.26.2. Their
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

`bytes` erases discarded exclusive `BytesMut` regions and retired backing
allocations, including growth and compaction. Shared backing storage is erased
before its last owner releases it. Live immutable `Bytes` aliases keep their
contents; wiping them would invalidate other users. Static slices and arbitrary
`Bytes::from_owner` owners keep their original ownership contract. Unsafe
`BytesMut::set_len` retains its documented no-write behavior and requires the
caller to manage initialized and discarded data. Ordinary `Vec` output transfers
remain caller-owned. The patch is unconditional, including transitive users.

`hyper` uses the patched mutable backing for its HTTP/1 serialized headers,
trailers and flattened body queue. Consuming output, compacting the cursor and
reusing storage erase discarded bytes. `tungstenite` guards its output queue,
fragment collectors, masked formatting temporaries and handshake read/write
storage before they can contain payload data. Their growth and error paths
erase retired allocations. Public message/HTTP values remain caller-owned.

HTTP/2's h2/tokio-util frame storage and tonic's gRPC encode/decode buffers use
the patched `BytesMut`/`Bytes` backing. They do not require a separate protocol
fork. These guarantees cover those byte allocations, not every container,
header table, optional compressor or caller-supplied body type in a transport.
Hyper's HTTP/2 upgraded tunnels use a separate boxed cursor that Maki does not
use; that allocation is outside this patch's coverage.

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
buffers and kernel buffers are separate owners. Compiler-created copies of
inline values or moved temporaries are outside
allocation-owner tracking. Shared immutable views retain
their allocation until the last owner releases it. Process termination that
skips destructors cannot provide
normal Drop cleanup. Page locking and total memory bounds remain separate.

To update a patched library, start from the new published archive, verify its
checksum, reapply and review each ownership change, and rerun the erasure
regressions and protocol tests before changing the pinned version. Inspect new
features and new allocation/clear/consume/shrink paths; an unchanged public API
does not prove the same internal lifetimes. Update the upstream inventory and
patch manifest together. CI runs the dependency contract and the explicit vendor
tests because these packages are excluded from workspace membership.
