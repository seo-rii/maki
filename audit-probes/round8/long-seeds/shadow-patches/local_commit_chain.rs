
// ---------------------------------------------------------------------------
// AUDIT ROUND 8 (long-seeds), appended in the shadow copy only: the COMMIT
// path of a local rollback-protected backing under the executable crash
// model. The committed crash sweeps cover creation, restore and the witness
// initialisation; nothing loses power in the middle of ordinary commits
// (file data syncs and directory syncs through `RollbackBacking`, each one a
// manifest publication plus a witness anchor update), because the public
// constructors take filesystem paths. `create_backing` / `open_witnessed`
// (added for the creation sweeps) make it possible.
//
// One seed = a volume and a random sequence of steps. A step writes one or
// two small files and syncs them and the directory; it may be cut by a
// process death or one failed backing operation of either machine. Between
// steps: nothing, a restart, a power loss of both machines (worst case or
// sampled, torn writes), or the two lopsided outcomes of one power loss
// (backing kept nothing volatile while the witness kept everything, and the
// reverse). Oracle: the volume always opens again, never as a refusal; a
// file whose sync returned to a live process keeps that content or shows a
// later attempted one; nothing else ever appears.

/// A generator whose every `random_bool(0.5)` is true and `random_bool(0.3)`
/// is false: `crash` then keeps every volatile operation, untorn.
struct KeepAll;

impl rand::RngCore for KeepAll {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        // 0.4 * 2^64: below one half, above three tenths.
        0x6666_6666_6666_6666
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0x66);
    }
}

const A8_FILES: [&str; 3] = ["f0", "f1", "f2"];
const A8_LEN: usize = 64;

fn a8_value(file: usize, stamp: u32) -> Vec<u8> {
    let mut v = vec![0u8; A8_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (stamp as usize * 31 + file * 7 + i) as u8 | 1;
    }
    v[..4].copy_from_slice(&stamp.to_le_bytes());
    v[4] = file as u8 + 1;
    v
}

#[derive(Clone, Default)]
struct A8File {
    /// Content a successful `sync_data` (with a durable name) acknowledged.
    durable: Option<Vec<u8>>,
    /// The name survived a successful `sync_dir`.
    name_durable: bool,
    /// Data acknowledged by `sync_data` while the name was not durable yet.
    synced_unnamed: Option<Vec<u8>>,
    /// Contents written since the acknowledgement: any may surface.
    maybe: Vec<Vec<u8>>,
}

/// What a fresh open shows of one file: absent, empty, or its bytes.
fn a8_read(backing: &RollbackBacking, name: &str) -> Result<Option<Vec<u8>>, String> {
    let file = match backing.open(name, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("open {name}: {error}")),
    };
    let len = file.len().map_err(|e| format!("len {name}: {e}"))? as usize;
    let mut bytes = vec![0u8; len];
    file.read_at(0, &mut bytes)
        .map_err(|e| format!("read {name}: {e}"))?;
    Ok(Some(bytes))
}

#[test]
fn audit8_commits_survive_interruptions_and_power_losses() {
    use rand::Rng;
    let mut stats = [0u64; 8];
    let mut failures: Vec<String> = Vec::new();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for seed in crate::a8::seeds(0..=200) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut local = [0u64; 8];
            let mut rng = StdRng::seed_from_u64(seed ^ 0xA8C4_0005);
            let machines = machines();
            let mut model: Vec<A8File> = vec![A8File::default(); A8_FILES.len()];
            let mut history = format!("seed {seed}");
            let mut stamp = 0u32;
            let mut volume = Some(machines.create().expect("undisturbed creation"));

            for _ in 0..rng.random_range(4..28) {
                // ---- one step, possibly cut
                let mode = rng.random_range(0..10u32); // 0..=5 none, 6..=7 single, 8..=9 death
                let cut = rng.random_range(0..40usize);
                if mode >= 6 {
                    let single = mode <= 7;
                    machines.inject(move |index| if single { index == cut } else { index >= cut });
                }
                let backing = volume.as_ref().expect("an open volume");
                let mut failed: Option<String> = None;
                let mut touched = Vec::new();
                for _ in 0..rng.random_range(1..=2) {
                    let index = rng.random_range(0..A8_FILES.len());
                    stamp += 1;
                    let value = a8_value(index, stamp);
                    touched.push(index);
                    // From the first call on the content may reach the disk.
                    model[index].maybe.push(value.clone());
                    let result = (|| -> io::Result<()> {
                        let file = backing.open(A8_FILES[index], true)?;
                        file.write_at(0, &value)?;
                        file.sync_data()
                    })();
                    match result {
                        Ok(()) => {
                            // Acknowledged to a live process.
                            if model[index].name_durable {
                                model[index].durable = Some(value);
                                model[index].maybe.clear();
                            } else {
                                model[index].synced_unnamed = Some(value);
                            }
                            local[0] += 1;
                        }
                        Err(error) => {
                            failed = Some(format!("{}: {error}", A8_FILES[index]));
                            break;
                        }
                    }
                }
                if failed.is_none() {
                    match backing.sync_dir("") {
                        Ok(()) => {
                            // Every name created so far is durable; data
                            // synced before its name was is durable with it.
                            for (index, file) in model.iter_mut().enumerate() {
                                let exists = backing.exists(A8_FILES[index]).unwrap_or(false);
                                if exists && !file.name_durable {
                                    file.name_durable = true;
                                    if let Some(value) = file.synced_unnamed.take() {
                                        file.durable = Some(value);
                                        // Later attempts stay possible.
                                        let keep_from = file
                                            .maybe
                                            .iter()
                                            .position(|v| Some(v) == file.durable.as_ref())
                                            .map(|p| p + 1)
                                            .unwrap_or(0);
                                        file.maybe.drain(..keep_from);
                                    }
                                }
                            }
                            local[1] += 1;
                        }
                        Err(error) => failed = Some(format!("sync_dir: {error}")),
                    }
                }
                machines.heal();
                history += &format!(
                    "\n  step files {touched:?} up to stamp {stamp} mode {} cut {cut} -> {}",
                    ["none", "single", "death"][match mode {
                        0..=5 => 0,
                        6..=7 => 1,
                        _ => 2,
                    }],
                    failed.as_deref().unwrap_or("ok")
                );

                // ---- what happens next
                let event = if failed.is_some() {
                    rng.random_range(1..=5u32)
                } else {
                    [0u32, 0, 0, 0, 1, 2, 2, 3, 4, 5][rng.random_range(0..10)]
                };
                if event == 0 {
                    continue;
                }
                drop(volume.take());
                let power_lost = match event {
                    1 => false,
                    2 => {
                        machines.power_loss(0);
                        true
                    }
                    3 => {
                        machines.power_loss(rng.random_range(1..u64::MAX));
                        true
                    }
                    4 => {
                        machines.root.crash_all_lost();
                        machines.witness.crash(&mut KeepAll);
                        true
                    }
                    _ => {
                        machines.root.crash(&mut KeepAll);
                        machines.witness.crash_all_lost();
                        true
                    }
                };
                local[2 + event as usize] += 1;
                history += [
                    "",
                    "\n  restart",
                    "\n  power loss: both lose everything volatile",
                    "\n  power loss: sampled, torn",
                    "\n  power loss: backing loses everything volatile, witness keeps everything",
                    "\n  power loss: backing keeps everything, witness loses everything volatile",
                ][event as usize];

                let reopened = match machines.open() {
                    Ok(reopened) => reopened,
                    Err(error) => panic!(
                        "OPEN-REFUSED: {error}; backing {:?}, witness {:?}\n{history}",
                        machines.root.process().list("").unwrap(),
                        machines.witness.process().list("").unwrap()
                    ),
                };
                for (index, file) in model.iter_mut().enumerate() {
                    let seen = a8_read(&reopened, A8_FILES[index])
                        .unwrap_or_else(|error| panic!("READ: {error}\n{history}"));
                    let unsynced_ok = |bytes: &Vec<u8>| {
                        file.maybe.contains(bytes) || file.synced_unnamed.as_ref() == Some(bytes)
                    };
                    match (&seen, &file.durable) {
                        (Some(bytes), Some(durable)) => assert!(
                            bytes == durable || unsynced_ok(bytes),
                            "CONTENT: {} holds {:02x?}.. , acknowledged stamp {:02x?}..\n{history}",
                            A8_FILES[index],
                            &bytes[..bytes.len().min(5)],
                            &durable[..5]
                        ),
                        (None, Some(_)) => panic!(
                            "LOST: {} is gone although its data and name were synced\n{history}",
                            A8_FILES[index]
                        ),
                        (Some(bytes), None) => assert!(
                            bytes.is_empty() || unsynced_ok(bytes),
                            "CONTENT: {} (never acknowledged) holds {:02x?}..\n{history}",
                            A8_FILES[index],
                            &bytes[..bytes.len().min(5)]
                        ),
                        (None, None) => assert!(
                            !file.name_durable,
                            "LOST: the durable name {} is gone\n{history}",
                            A8_FILES[index]
                        ),
                    }
                    if power_lost {
                        // What survived a power loss is the durable state.
                        file.name_durable = seen.is_some();
                        file.durable = seen.filter(|bytes| !bytes.is_empty());
                        file.synced_unnamed = None;
                        file.maybe.clear();
                    }
                }
                history += " -> opened";
                volume = Some(reopened);
            }
            local
        }));
        match outcome {
            Ok(local) => {
                for (total, n) in stats.iter_mut().zip(local) {
                    *total += n;
                }
            }
            Err(payload) => {
                let text = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                failures.push(text);
            }
        }
    }
    std::panic::set_hook(previous);
    println!(
        "AUDIT8 local commit chains: data syncs acknowledged {}, directory syncs {}, restarts {}, power \
         losses: worst-case {}, sampled {}, backing-lost/witness-kept {}, backing-kept/witness-lost {}; \
         failing seeds {}",
        stats[0], stats[1], stats[3], stats[4], stats[5], stats[6], stats[7], failures.len()
    );
    let mut classes = std::collections::BTreeMap::new();
    for text in &failures {
        *classes
            .entry(text.split(':').next().unwrap_or("?").to_string())
            .or_insert(0u32) += 1;
    }
    assert!(
        failures.is_empty(),
        "{} failing seed(s), classes {classes:?}; first:\n{}",
        failures.len(),
        failures[0].chars().take(6000).collect::<String>()
    );
}
