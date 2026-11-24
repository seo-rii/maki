# Round-8 audit probes (main 956e354)

Reproductions and harnesses from the eighth audit, which looked at the tree
after rounds 6 and 7 (the helper-owned NBD connection, the RPM package and
the release workflow) by angle. The Rust tests are the `audit8_*.rs` files
under the crates' `tests/` directories; several fail on purpose on the
audited tree (they demonstrate a finding), and most sweeps are `#[ignore]`d.
The verified findings and what was done about each are in
`docs/review-remediation.md` on `main` (eighth round).

- `privileged-nbd/`: the difference between the helper's source and the
  mirror that `crates/maki-privileged/tests/audit8_mirror/` compiles by path
  (the directory holds symbolic links into `src/`; do not run `rustfmt` on
  it). `audit8_kernel_semantics.rs` models the CentOS Stream 9 NBD driver's
  connect, busy and disconnect answers.
- `native-nbdkit/`: Python clients and a preload shim that drive the plugin
  inside a real nbdkit (power-loss images, concurrency, exhaustion, the
  fast-zero abort, an interrupted `create`). `NOTES.md` says how to run them.
- `installed-packages/`: scripts that install the released `.deb` in a
  Debian 12 root and the RPM in a CentOS Stream 9 root and replay the
  guides, including the `dnf remove` reproduction.
- `merge-interactions/`: reproductions of a local `create` killed after its
  anchor is published, and the CLI probes.
- `docs/`: scripts that extracted and ran the documents' command blocks and
  compared quoted messages with the binaries' output.
- `long-seeds/`: the job scripts of the seed and fuzz campaign, the patches
  that build mutated ("shadow") crates, and the seed generator.
