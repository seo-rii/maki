
// ---------------------------------------------------------------------------
// AUDIT ROUND 8 (long-seeds), appended in the shadow copy only. The committed
// sweeps inject ONE fault per lifecycle. Here every invocation of the
// packaged failed-start path (attach, the ExecStopPost hook, the
// coordinator's cleanup) and of the teardown path (detach or cleanup, then a
// cleanup retry) gets its own random fault. Oracles are the committed ones:
// whatever is live is named by the trusted record after every invocation;
// fault-free cleanup retries converge, allowing only the documented state
// nothing can deactivate without the daemon (one manual mapping removal);
// and the next attach succeeds.
struct A8Rng(u64);

impl A8Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn fault(&mut self, commands: usize, observations: usize) -> Option<Fault> {
        match self.below(10) {
            0 => None,
            1..=6 => Some(Fault::Command {
                at: 1 + self.below(commands as u64 + 2) as usize,
                end: ENDS[self.below(4) as usize],
                took_effect: self.below(2) == 0,
            }),
            _ => Some(Fault::Observation {
                at: 1 + self.below(observations as u64 + 2) as usize,
                helper_dies: self.below(2) == 0,
            }),
        }
    }
}

fn a8_seed_range(default: u64) -> std::ops::Range<u64> {
    let get = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
    match (get("AUDIT8_SEED_START"), get("AUDIT8_SEED_COUNT")) {
        (Some(start), Some(count)) => start..start + count,
        (Some(start), None) => start..start + default,
        (None, Some(count)) => 0..count,
        (None, None) => 0..default,
    }
}

fn a8_note(problems: &mut Vec<String>, context: &str, result: Result<(), String>) {
    if let Err(problem) = result {
        problems.push(format!("{context}: {problem}"));
    }
}

#[test]
fn audit8_random_fault_in_every_invocation_converges() {
    silence_simulated_deaths();
    let mut baseline = Case::new();
    assert_eq!(baseline.run(None, Verb::Attach), Outcome::Done);
    let (commands, observations) = baseline.points();
    let mut problems = Vec::new();
    let mut stats = [0u64; 6];
    for seed in a8_seed_range(2000) {
        let mut rng = A8Rng(seed ^ 0xA8C4_0004);
        let mut case = Case::new();
        case.world.lvm_select_matches_nothing = rng.below(2) == 0;
        let mut context = format!("seed {seed}");
        let f1 = rng.fault(commands, observations);
        let first = case.run(f1, Verb::Attach);
        context += &format!("; attach {f1:?} -> {first:?}");
        a8_note(&mut problems, &context, case.record_covers_live_state());

        if first == Outcome::Done {
            // Attached: a faulted teardown, then a faulted cleanup retry.
            stats[0] += 1;
            if !case.fully_attached() {
                problems.push(format!("{context}: success without a complete attachment"));
                continue;
            }
            let daemon_stopped = rng.below(3) == 0;
            if daemon_stopped {
                case.world.stop_daemon();
            }
            let verb = if !daemon_stopped && rng.below(2) == 0 {
                Verb::Detach
            } else {
                Verb::Cleanup
            };
            let f2 = rng.fault(commands, observations);
            let mut last = case.run(f2, verb);
            context += &format!("; {verb:?} (daemon stopped {daemon_stopped}) {f2:?} -> {last:?}");
            a8_note(&mut problems, &context, case.record_covers_live_state());
            if last != Outcome::Done {
                let f3 = rng.fault(commands, observations);
                last = case.run(f3, Verb::Cleanup);
                context += &format!("; cleanup {f3:?} -> {last:?}");
                a8_note(&mut problems, &context, case.record_covers_live_state());
            }
            let mut retries = Vec::new();
            for _ in 0..3 {
                if last == Outcome::Done {
                    break;
                }
                last = case.run(None, Verb::Cleanup);
                retries.push(last.clone());
            }
            if last != Outcome::Done || !case.clean() {
                problems.push(format!(
                    "{context}: retries {retries:?} left {:?}, record {}",
                    case.live(),
                    case.record().is_some()
                ));
                continue;
            }
            stats[1] += 1;
            a8_note(&mut problems, &context, case.restart());
            continue;
        }

        // A failed start: the hook, then the coordinator, each faulted.
        stats[2] += 1;
        let f2 = rng.fault(commands, observations);
        let hook = case.run(f2, Verb::FailedStartHook);
        context += &format!("; hook {f2:?} -> {hook:?}");
        a8_note(&mut problems, &context, case.record_covers_live_state());
        case.world.stop_daemon();
        let f3 = rng.fault(commands, observations);
        let mut cleanup = case.run(f3, Verb::Cleanup);
        context += &format!("; cleanup {f3:?} -> {cleanup:?}");
        a8_note(&mut problems, &context, case.record_covers_live_state());
        let mut manual = false;
        for _ in 0..3 {
            if cleanup == Outcome::Done {
                break;
            }
            cleanup = case.run(None, Verb::Cleanup);
            a8_note(&mut problems, &context, case.record_covers_live_state());
            if cleanup != Outcome::Done && case.live() == (true, true, false) && !manual {
                // The documented state nothing can deactivate without the
                // daemon: the operator removes the unused mapping by hand.
                if case.ran("dmsetup-remove") {
                    problems.push(format!("{context}: cleanup ran dmsetup-remove and still refused"));
                }
                case.world.remove_unused_mapping_by_hand();
                manual = true;
                stats[3] += 1;
            }
        }
        if cleanup != Outcome::Done || !case.clean() {
            problems.push(format!(
                "{context}: cleanup did not converge (manual removal {manual}): {cleanup:?}, left {:?}, \
                 record {}",
                case.live(),
                case.record().is_some()
            ));
            continue;
        }
        stats[4] += 1;
        a8_note(&mut problems, &context, case.restart());
        stats[5] += 1;
    }
    println!(
        "AUDIT8 step-fault chains: attached-then-teardown {} (converged {}), failed starts {} (manual \
         removals {}, converged {}, restarted {}), problems {}",
        stats[0], stats[1], stats[2], stats[3], stats[4], stats[5], problems.len()
    );
    assert!(
        problems.is_empty(),
        "{} problem(s); first 10:\n{}",
        problems.len(),
        problems.iter().take(10).cloned().collect::<Vec<_>>().join("\n")
    );
}
