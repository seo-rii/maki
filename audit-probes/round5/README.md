# Round-5 audit probes (main e6f52d6)

Reproductions and harnesses from the fifth audit. The Rust tests are the
`audit5_*.rs` files under the crates' `tests/` directories; several fail on
purpose on the audited tree (they demonstrate a finding) and several are
`#[ignore]`d sweeps that need `strace` and root.

- `privileged-steps/audit5_steps.rs`: a simulated-kernel harness for the
  privileged helper. It uses crate-private seams, so it is not an integration
  test: copy it into `crates/maki-privileged/src/` and append
  `#[cfg(test)] #[path = "audit5_steps.rs"] mod audit5_steps;` to `exec.rs`.
- `docs-config/`, `docs-spec/`: scripts that generated configuration probes
  and resolved test and file names cited in the documents.
- `test-robustness/`: scripts that ran each crate's test binaries under
  `umask 002`, as an unprivileged user, at high parallelism and in isolation.
- `merge-interactions/`: `strace` traces of the local witness republish.
