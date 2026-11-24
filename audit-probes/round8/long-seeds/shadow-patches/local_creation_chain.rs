
// ---------------------------------------------------------------------------
// AUDIT ROUND 8 (long-seeds), appended in the shadow copy only.
// The committed sweeps interrupt a creation ONCE and then complete it. Here
// a creation (or the daemon's start) is interrupted one to four times in a
// row, each time at a random operation as a process death or a single failed
// operation, each optionally followed by a power loss, before the committed
// `complete` protocol is required to finish the pair.
#[test]
fn audit8_a_creation_interrupted_repeatedly_can_be_continued() {
    use rand::Rng;
    let ops = operations();
    let mut stats = [0u64; 4];
    for seed in crate::a8::seeds(0..=300) {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xA8C4_0001);
        let machines = machines();
        let mut context = format!("seed {seed}");
        // A creation that really reported success (the process lived).
        let mut created = false;
        for _ in 0..rng.random_range(1..=4) {
            let cut = rng.random_range(0..=ops + 2);
            let single = rng.random_bool(0.3);
            let open_instead = rng.random_bool(0.3);
            let injected = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let seen = injected.clone();
            machines.inject(move |index| {
                let fail = if single { index == cut } else { index >= cut };
                if fail {
                    seen.store(true, Ordering::SeqCst);
                }
                fail
            });
            let ok = if open_instead {
                machines.open().map(drop).is_ok()
            } else {
                machines.create().map(drop).is_ok()
            };
            machines.heal();
            let disturbed = injected.load(Ordering::SeqCst);
            // A dead process reports nothing; a live one's success is real.
            if ok && !open_instead && (single || !disturbed) {
                created = true;
                stats[0] += 1;
            }
            let loss = rng.random_range(0..4u64);
            match loss {
                0 => {}
                1 => machines.power_loss(0),
                _ => machines.power_loss(rng.random_range(1..u64::MAX)),
            }
            stats[1] += 1;
            context += &format!(
                "; {} cut {cut}{} -> ok={ok} disturbed={disturbed}, loss {loss}",
                if open_instead { "open" } else { "create" },
                if single { " (single failure)" } else { " (death)" },
            );
            if created {
                // Whatever came after it, a reported creation still opens.
                let opened = machines.open();
                assert!(
                    opened.is_ok(),
                    "{context}: a creation that reported success no longer opens: {:?}",
                    opened.err()
                );
                stats[2] += 1;
            }
        }
        complete(&machines, &context);
        stats[3] += 1;
    }
    println!(
        "AUDIT8 local creation chains: seeds completed {}, interrupted commands {}, real successes {}, \
         reopen checks {}",
        stats[3], stats[1], stats[0], stats[2]
    );
}
