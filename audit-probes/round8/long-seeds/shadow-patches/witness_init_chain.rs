
// ---------------------------------------------------------------------------
// AUDIT ROUND 8 (long-seeds), appended in the shadow copy only: `init` and
// `serve` interrupted one to four times in a row (random operation, process
// death or single failed operation, optional power loss) before the
// committed `continued` protocol. An initialization that really reported
// success (its process lived) must never be accepted by `init` again.
#[test]
fn audit8_an_init_interrupted_repeatedly_can_be_run_again_or_served() {
    use rand::Rng;
    let ops = initial_operations();
    let mut done = 0u64;
    let mut commands = 0u64;
    let mut enrolled_checks = 0u64;
    for seed in crate::a8::seeds(0..=300) {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xA8C4_0003);
        let machine = machine();
        let mut context = format!("seed {seed}");
        let mut enrolled = false;
        for _ in 0..rng.random_range(1..=4) {
            let cut = rng.random_range(0..=ops + 2);
            let single = rng.random_bool(0.3);
            let serve_instead = rng.random_bool(0.3);
            let injected = Arc::new(AtomicBool::new(false));
            let seen = injected.clone();
            inject(&machine, move |index| {
                let fail = if single { index == cut } else { index >= cut };
                if fail {
                    seen.store(true, Ordering::SeqCst);
                }
                fail
            });
            let ok = if serve_instead {
                serve(&machine).map(drop).is_ok()
            } else {
                init(&machine).map(drop).is_ok()
            };
            machine.set_fault_hook(None);
            let disturbed = injected.load(Ordering::SeqCst);
            if ok && !serve_instead && (single || !disturbed) {
                enrolled = true;
            }
            let loss = rng.random_range(0..4u64);
            match loss {
                0 => {}
                1 => machine.crash_all_lost(),
                _ => machine.crash(&mut StdRng::seed_from_u64(rng.random_range(1..u64::MAX))),
            }
            commands += 1;
            context += &format!(
                "; {} cut {cut}{} -> ok={ok} disturbed={disturbed}, loss {loss}",
                if serve_instead { "serve" } else { "init" },
                if single { " (single failure)" } else { " (death)" },
            );
            if enrolled {
                enrolled_checks += 1;
                assert_eq!(
                    init(&machine).err().map(|error| error.kind()),
                    Some(io::ErrorKind::AlreadyExists),
                    "{context}: an authority whose init reported success was initialized again"
                );
                serves_the_initial_record(&machine, &context);
            }
        }
        continued(&machine, &context);
        done += 1;
    }
    println!(
        "AUDIT8 witness init chains: seeds completed {done}, interrupted commands {commands}, \
         enrolled checks {enrolled_checks}"
    );
}
