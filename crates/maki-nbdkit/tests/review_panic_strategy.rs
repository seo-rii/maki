//! The nbdkit callbacks, the adapter's engine calls and plugin startup turn a
//! panic into EIO or a failed start with `catch_unwind`. Under
//! `panic = "abort"` (a profile override such as
//! `CARGO_PROFILE_RELEASE_PANIC=abort`, or `-C panic=abort` in `RUSTFLAGS`)
//! there is nothing to catch: the first panic aborts nbdkit with every
//! connection. The crate must refuse to build that way. The guard lives in a
//! file with no other items, so it compiles on its own here without the
//! crate's dependencies.

use std::path::Path;
use std::process::{Command, Output};

const GUARD: &str = "src/panic_strategy.rs";

fn compile_guard(strategy: &str) -> Output {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guard = manifest.join(GUARD);
    assert!(
        guard.is_file(),
        "{GUARD} must hold the panic strategy guard"
    );
    let out = tempfile::tempdir().unwrap();
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    Command::new(rustc)
        // rustup selects the same toolchain as for the crate itself.
        .current_dir(manifest)
        .args(["--edition=2021", "--crate-type=lib", "--emit=metadata"])
        .args(["--crate-name=panic_strategy_guard", "-C"])
        .arg(format!("panic={strategy}"))
        .arg("--out-dir")
        .arg(out.path())
        .arg(&guard)
        .output()
        .expect("rustc must be runnable to check the panic strategy guard")
}

#[test]
fn the_crate_refuses_to_build_without_unwinding_panics() {
    let abort = compile_guard("abort");
    let stderr = String::from_utf8_lossy(&abort.stderr);
    assert!(
        !abort.status.success(),
        "panic = \"abort\" must not compile"
    );
    assert!(
        stderr.contains("maki-nbdkit requires panic = \"unwind\""),
        "the build error must name the required strategy: {stderr}"
    );
    let unwind = compile_guard("unwind");
    assert!(
        unwind.status.success(),
        "panic = \"unwind\" must compile: {}",
        String::from_utf8_lossy(&unwind.stderr)
    );
}

#[test]
fn the_guard_is_compiled_into_the_crate() {
    let lib = include_str!("../src/lib.rs");
    assert!(
        lib.lines().any(|line| line.trim() == "mod panic_strategy;"),
        "lib.rs must include the panic strategy guard"
    );
}
