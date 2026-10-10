//! Durable, single-volume remote freshness authority and its exact-CAS protocol.
//!
//! The independent authority must never be restored with a backing snapshot.
//! A fresh physical namespace for each session fences old storage writers.

use std::io;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::witness::Anchor;
use sha2::{Digest, Sha256};

use crate::{Backing, FileBacking, VolumeLock};

const STATE_FILE: &str = "remote.state";
const TEMP_FILE: &str = "remote.next";
const LOCK_FILE: &str = "remote.lock";
const MAGIC: &[u8; 8] = b"MAKIRW01";
const MAX_BYTES: usize = 64 * 1024;
const MAX_GENERATION: u64 = i64::MAX as u64;
const STATE_DOMAIN: &[u8] = b"maki-remote-witness-state-v1\0";
const REQUEST_DOMAIN: &[u8] = b"maki-remote-witness-request-v1\0";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "administrator authority required",
    )
}
fn conflict() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "remote witness comparison failed",
    )
}
fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}
fn increment(value: u64, maximum: u64) -> io::Result<u64> {
    value
        .checked_add(1)
        .filter(|v| *v <= maximum)
        .ok_or_else(|| input("remote witness counter exhausted"))
}
fn namespace_fence(value: &str) -> io::Result<u64> {
    if value.len() != 56 || !value.starts_with("remote-") || value.as_bytes()[23] != b'-' {
        return Err(invalid("invalid remote namespace"));
    }
    let bytes = value.as_bytes();
    if !bytes[7..23]
        .iter()
        .chain(&bytes[24..])
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(invalid("invalid remote namespace encoding"));
    }
    let fence = u64::from_str_radix(&value[7..23], 16)
        .map_err(|_| invalid("invalid remote namespace fence"))?;
    if fence == 0 || bytes[24..].iter().all(|b| *b == b'0') {
        return Err(invalid("nil remote namespace session or fence"));
    }
    Ok(fence)
}

impl Descriptor {
    pub fn validate(&self) -> io::Result<()> {
        if self.anchor.identity == [0; 16]
            || self.anchor.generation > MAX_GENERATION
            || self.epoch > self.anchor.generation
        {
            return Err(invalid("invalid remote descriptor identity or counters"));
        }
        namespace_fence(&self.namespace)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub anchor: Anchor,
    pub epoch: u64,
    pub namespace: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Released,
    Claimed,
    RestoreClaimed,
    Active,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub identity: [u8; 16],
    pub current: Option<Descriptor>,
    pub fence: u64,
    pub session: [u8; 16],
    pub phase: Phase,
    pub restore_source: Option<Descriptor>,
    pub last_operation: [u8; 16],
}

impl Record {
    pub fn validate(&self) -> io::Result<()> {
        if self.identity == [0; 16] {
            return Err(invalid("nil remote witness identity"));
        }
        if self.fence == 0 {
            if self.current.is_some()
                || self.session != [0; 16]
                || self.phase != Phase::Released
                || self.restore_source.is_some()
                || self.last_operation != [0; 16]
            {
                return Err(invalid("invalid initial remote witness record"));
            }
            return Ok(());
        }
        if self.session == [0; 16] || self.last_operation == [0; 16] {
            return Err(invalid("nil remote witness operation or session"));
        }
        if let Some(current) = &self.current {
            current.validate()?;
            if current.anchor.identity != self.identity
                || namespace_fence(&current.namespace)? > self.fence
            {
                return Err(invalid(
                    "remote witness descriptor is outside its identity or fence",
                ));
            }
            if self.phase == Phase::Active
                && current.namespace != namespace(self.fence, self.session)
            {
                return Err(invalid("active remote namespace differs from its session"));
            }
        } else if matches!(self.phase, Phase::Active | Phase::RestoreClaimed) {
            return Err(invalid(
                "remote witness phase requires a current descriptor",
            ));
        }
        match (&self.restore_source, self.phase) {
            (Some(source), Phase::RestoreClaimed) => {
                source.validate()?;
                let current = self
                    .current
                    .as_ref()
                    .ok_or_else(|| invalid("restore has no current descriptor"))?;
                if source.anchor.identity != self.identity
                    || source.anchor.generation > current.anchor.generation
                    || source.epoch > current.epoch
                    || namespace_fence(&source.namespace)? > self.fence
                {
                    return Err(invalid("invalid remote restore source"));
                }
            }
            (None, Phase::RestoreClaimed) | (Some(_), _) => {
                return Err(invalid("remote restore source does not match phase"))
            }
            (None, _) => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Inspect,
    Claim,
    Takeover,
    ClaimRestore { source: Descriptor },
    Activate { descriptor: Descriptor },
    Advance { anchor: Anchor },
    Release,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation_id: [u8; 16],
    pub expected: Option<Record>,
    pub action: Action,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Writer,
    Admin,
}

pub trait Rpc: Send + Sync {
    fn call(&self, request: &Request) -> io::Result<Record>;
}

pub fn namespace(fence: u64, session: [u8; 16]) -> String {
    let suffix: String = session.iter().map(|b| format!("{b:02x}")).collect();
    format!("remote-{fence:016x}-{suffix}")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: u32,
    record: Record,
    last_request_hash: Option<[u8; 32]>,
}

impl Stored {
    fn validate(&self) -> io::Result<()> {
        if self.format != 1 || self.last_request_hash.is_some() != (self.record.fence != 0) {
            return Err(invalid("unsupported or inconsistent remote witness format"));
        }
        self.record.validate()
    }
}

/// A separately persisted freshness authority for exactly one volume.
///
/// Its stable lock covers every request and must outlive the server. Errors
/// during persistence poison the handle: reopen and resolve the exact request
/// before proceeding. The authority directory must never follow data restores.
pub struct StateStore {
    backing: Arc<dyn Backing>,
    stored: Stored,
    poisoned: bool,
    _lock: Box<dyn VolumeLock>,
}

impl StateStore {
    /// Explicitly enroll an authority; existing state, even corrupt, refuses.
    pub fn create(path: &Path, identity: [u8; 16]) -> io::Result<Self> {
        if identity == [0; 16] {
            return Err(input("nil remote witness identity"));
        }
        Self::create_backing(Arc::new(FileBacking::new(path)?), identity)
    }

    /// Open an enrolled authority. Serving never implicitly initializes it.
    pub fn open(path: &Path) -> io::Result<Self> {
        if !std::fs::metadata(path)?.is_dir() {
            return Err(input("remote witness path is not a directory"));
        }
        Self::open_backing(Arc::new(FileBacking::new(path)?))
    }

    /// The backing must uphold `Backing`'s persistence and exclusive-lock contract.
    pub fn create_backing(backing: Arc<dyn Backing>, identity: [u8; 16]) -> io::Result<Self> {
        if identity == [0; 16] {
            return Err(input("nil remote witness identity"));
        }
        let lock = backing.try_lock(LOCK_FILE)?;
        if backing.exists(STATE_FILE)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "remote witness already enrolled",
            ));
        }
        let stored = Stored {
            format: 1,
            record: Record {
                identity,
                current: None,
                fence: 0,
                session: [0; 16],
                phase: Phase::Released,
                restore_source: None,
                last_operation: [0; 16],
            },
            last_request_hash: None,
        };
        // Confined rename requires an existing destination. The synced empty
        // sentinel makes interrupted enrollment invalid, never silently usable.
        let placeholder = backing.open(STATE_FILE, true)?;
        placeholder.set_len(0)?;
        placeholder.sync_data()?;
        backing.sync_dir("")?;
        publish(backing.as_ref(), &stored)?;
        Ok(Self {
            backing,
            stored,
            poisoned: false,
            _lock: lock,
        })
    }

    /// Re-publish selected page-cache bytes before acknowledging any request.
    pub fn open_backing(backing: Arc<dyn Backing>) -> io::Result<Self> {
        let lock = backing.try_lock(LOCK_FILE)?;
        let stored = read(backing.as_ref())?;
        publish(backing.as_ref(), &stored)?;
        Ok(Self {
            backing,
            stored,
            poisoned: false,
            _lock: lock,
        })
    }

    /// Apply a full-record CAS, or replay only the most recent exact request.
    ///
    /// The role comes from authenticated transport credentials, never the body.
    /// No retry can bypass its original authorization: the role is included in
    /// the durable operation digest. A failed comparison never mutates state.
    pub fn handle(&mut self, role: Role, request: &Request) -> io::Result<Record> {
        if self.poisoned {
            return Err(io::Error::other(
                "remote witness state uncertain; reopen required",
            ));
        }
        let current = read(self.backing.as_ref());
        match current {
            Ok(current) if current == self.stored => {}
            Ok(_) => {
                self.poisoned = true;
                return Err(invalid("remote witness changed while locked"));
            }
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        }
        if request.action == Action::Inspect {
            if request
                .expected
                .as_ref()
                .is_some_and(|r| r != &self.stored.record)
            {
                return Err(conflict());
            }
            return Ok(self.stored.record.clone());
        }
        if request.operation_id == [0; 16] {
            return Err(input("nil remote witness operation id"));
        }
        let encoded = serde_json::to_vec(&(role, request)).map_err(io::Error::other)?;
        if encoded.len() > MAX_BYTES {
            return Err(input("remote witness request too large"));
        }
        let request_hash = digest(REQUEST_DOMAIN, &encoded);
        if request.operation_id == self.stored.record.last_operation {
            return if self.stored.last_request_hash == Some(request_hash) {
                Ok(self.stored.record.clone())
            } else {
                Err(input(
                    "remote witness operation id reused with different request or role",
                ))
            };
        }
        if request.expected.as_ref() != Some(&self.stored.record) {
            return Err(conflict());
        }
        let mut next = self.stored.record.clone();
        transition(&mut next, role, request)?;
        next.last_operation = request.operation_id;
        next.validate()?;
        let stored = Stored {
            format: 1,
            record: next,
            last_request_hash: Some(request_hash),
        };
        if let Err(error) = publish(self.backing.as_ref(), &stored) {
            self.poisoned = true;
            return Err(error);
        }
        self.stored = stored;
        Ok(self.stored.record.clone())
    }
}

fn transition(next: &mut Record, role: Role, request: &Request) -> io::Result<()> {
    match &request.action {
        Action::Inspect => unreachable!("inspect handled before transition"),
        Action::Claim | Action::Takeover | Action::ClaimRestore { .. } => {
            match &request.action {
                Action::Claim if next.phase != Phase::Released => return Err(conflict()),
                Action::Takeover | Action::ClaimRestore { .. } if role != Role::Admin => {
                    return Err(denied())
                }
                _ => {}
            }
            if let Action::ClaimRestore { source } = &request.action {
                source.validate()?;
                let current = next
                    .current
                    .as_ref()
                    .ok_or_else(|| input("cannot restore an unenrolled backing"))?;
                if source.anchor.identity != next.identity
                    || source.anchor.generation > current.anchor.generation
                    || source.epoch > current.epoch
                    || namespace_fence(&source.namespace)? > next.fence
                {
                    return Err(input(
                        "restore source is not an earlier descriptor of this volume",
                    ));
                }
                increment(current.epoch, MAX_GENERATION)?;
                increment(current.anchor.generation, MAX_GENERATION)?;
                next.restore_source = Some(source.clone());
                next.phase = Phase::RestoreClaimed;
            } else {
                next.restore_source = None;
                next.phase = Phase::Claimed;
            }
            next.fence = increment(next.fence, u64::MAX)?;
            next.session = request.operation_id;
        }
        Action::Activate { descriptor } => {
            descriptor.validate()?;
            if descriptor.anchor.identity != next.identity
                || descriptor.namespace != namespace(next.fence, next.session)
            {
                return Err(input(
                    "activation must use the claimed volume and fresh namespace",
                ));
            }
            match next.phase {
                Phase::Claimed => {
                    if let Some(current) = &next.current {
                        if descriptor.anchor != current.anchor || descriptor.epoch != current.epoch
                        {
                            return Err(input("ordinary activation cannot change anchor or epoch"));
                        }
                    } else if descriptor.anchor.generation != 0 || descriptor.epoch != 0 {
                        return Err(input(
                            "initial activation requires generation and epoch zero",
                        ));
                    }
                }
                Phase::RestoreClaimed => {
                    if role != Role::Admin {
                        return Err(denied());
                    }
                    let current = next
                        .current
                        .as_ref()
                        .ok_or_else(|| invalid("restore has no current descriptor"))?;
                    if descriptor.anchor.generation
                        != increment(current.anchor.generation, MAX_GENERATION)?
                        || descriptor.epoch != increment(current.epoch, MAX_GENERATION)?
                    {
                        return Err(input(
                            "restore must advance current generation and epoch exactly once",
                        ));
                    }
                    // The administrator authenticates the recorded source and
                    // re-encodes its manifest with the new generation. Its hash
                    // therefore changes; it cannot equal the source's root.
                }
                _ => return Err(input("activation requires an outstanding claim")),
            }
            next.current = Some(descriptor.clone());
            next.restore_source = None;
            next.phase = Phase::Active;
        }
        Action::Advance { anchor } => {
            if next.phase != Phase::Active {
                return Err(input("advance requires active writer"));
            }
            let current = next
                .current
                .as_mut()
                .ok_or_else(|| invalid("active writer has no descriptor"))?;
            if anchor.identity != next.identity
                || anchor.generation != increment(current.anchor.generation, MAX_GENERATION)?
            {
                return Err(input(
                    "advance must increment current volume generation exactly once",
                ));
            }
            current.anchor = anchor.clone();
        }
        Action::Release => {
            if next.phase == Phase::Released {
                return Err(input("remote writer is already released"));
            }
            if next.phase == Phase::RestoreClaimed && role != Role::Admin {
                return Err(denied());
            }
            next.phase = Phase::Released;
            next.restore_source = None;
        }
    }
    Ok(())
}

fn encode(stored: &Stored) -> io::Result<Vec<u8>> {
    stored.validate()?;
    let body = serde_json::to_vec(stored).map_err(io::Error::other)?;
    if body.len() + 44 > MAX_BYTES {
        return Err(input("remote witness state too large"));
    }
    let mut bytes = Vec::with_capacity(body.len() + 44);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&body);
    let checksum = digest(STATE_DOMAIN, &bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> io::Result<Stored> {
    if bytes.len() < 44 || bytes.len() > MAX_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid("invalid remote witness envelope"));
    }
    let len = u32::from_le_bytes(bytes[8..12].try_into().expect("checked fixed length")) as usize;
    if len != bytes.len() - 44
        || digest(STATE_DOMAIN, &bytes[..bytes.len() - 32]) != bytes[bytes.len() - 32..]
    {
        return Err(invalid("remote witness length or checksum mismatch"));
    }
    let body = &bytes[12..12 + len];
    let stored: Stored =
        serde_json::from_slice(body).map_err(|_| invalid("invalid remote witness record"))?;
    stored.validate()?;
    if serde_json::to_vec(&stored).map_err(io::Error::other)? != body {
        return Err(invalid("noncanonical remote witness record"));
    }
    Ok(stored)
}

fn read(backing: &dyn Backing) -> io::Result<Stored> {
    let file = backing.open(STATE_FILE, false)?;
    let len = file.len()?;
    if !(44..=MAX_BYTES as u64).contains(&len) {
        return Err(invalid("invalid remote witness length"));
    }
    let mut bytes = vec![0; len as usize];
    file.read_at(0, &mut bytes)?;
    decode(&bytes)
}

fn publish(backing: &dyn Backing, stored: &Stored) -> io::Result<()> {
    let bytes = encode(stored)?;
    let file = backing.open(TEMP_FILE, true)?;
    file.set_len(0)?;
    file.write_at(0, &bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_data()?;
    backing.rename(TEMP_FILE, STATE_FILE)?;
    backing.sync_dir("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial() -> Stored {
        Stored {
            format: 1,
            record: Record {
                identity: [1; 16],
                current: None,
                fence: 0,
                session: [0; 16],
                phase: Phase::Released,
                restore_source: None,
                last_operation: [0; 16],
            },
            last_request_hash: None,
        }
    }

    fn active() -> Stored {
        let mut s = initial();
        s.record.fence = 1;
        s.record.session = [2; 16];
        s.record.last_operation = [3; 16];
        s.record.phase = Phase::Active;
        s.record.current = Some(Descriptor {
            anchor: Anchor {
                identity: [1; 16],
                generation: 4,
                root: [4; 32],
            },
            epoch: 0,
            namespace: namespace(1, [2; 16]),
        });
        s.last_request_hash = Some([5; 32]);
        s
    }

    fn wrap(body: &[u8]) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&(body.len() as u32).to_le_bytes());
        b.extend_from_slice(body);
        let sum = digest(STATE_DOMAIN, &b);
        b.extend_from_slice(&sum);
        b
    }

    #[test]
    fn initial_state_has_a_fixed_domain_separated_golden_vector() {
        let bytes = encode(&initial()).unwrap();
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hash,
            "ea09320612df918579eb6cb2c2527bc1b4884348dd9f4f00b3b89551ece992c8"
        );
        assert_eq!(decode(&bytes).unwrap(), initial());
    }

    #[test]
    fn checksum_valid_but_noncanonical_unknown_or_inconsistent_records_fail() {
        let initial = initial();
        let canonical = serde_json::to_vec(&initial).unwrap();
        let mut space = canonical.clone();
        space.push(b' ');
        assert!(decode(&wrap(&space)).is_err());
        let mut value = serde_json::to_value(&initial).unwrap();
        value["unknown"] = true.into();
        assert!(decode(&wrap(&serde_json::to_vec(&value).unwrap())).is_err());
        for field in 0..10 {
            let mut s = active();
            match field {
                0 => s.format = 2,
                1 => s.record.identity = [0; 16],
                2 => s.record.current.as_mut().unwrap().anchor.identity = [9; 16],
                3 => s.record.current.as_mut().unwrap().anchor.generation = u64::MAX,
                4 => s.record.current.as_mut().unwrap().epoch = 5,
                5 => s.record.current.as_mut().unwrap().namespace = namespace(2, [2; 16]),
                6 => s.record.session = [0; 16],
                7 => s.record.last_operation = [0; 16],
                8 => s.last_request_hash = None,
                _ => s.record.restore_source = s.record.current.clone(),
            }
            assert!(
                decode(&wrap(&serde_json::to_vec(&s).unwrap())).is_err(),
                "field {field}"
            );
        }
    }

    #[test]
    fn full_counter_space_cannot_wrap_to_a_reusable_session_or_generation() {
        let mut s = active();
        s.record.fence = u64::MAX;
        s.record.current.as_mut().unwrap().namespace = namespace(u64::MAX, s.record.session);
        let req = Request {
            operation_id: [7; 16],
            expected: Some(s.record.clone()),
            action: Action::Takeover,
        };
        assert!(transition(&mut s.record, Role::Admin, &req).is_err());
        let mut s = active();
        s.record.current.as_mut().unwrap().anchor.generation = MAX_GENERATION;
        let source = s.record.current.clone().unwrap();
        for action in [
            Action::Advance {
                anchor: Anchor {
                    identity: [1; 16],
                    generation: MAX_GENERATION + 1,
                    root: [6; 32],
                },
            },
            Action::ClaimRestore { source },
        ] {
            let req = Request {
                operation_id: [7; 16],
                expected: Some(s.record.clone()),
                action,
            };
            assert!(transition(&mut s.record.clone(), Role::Admin, &req).is_err());
        }
    }

    #[test]
    fn namespace_is_one_canonical_nonzero_component_without_escape_paths() {
        for value in [
            "../remote",
            "/remote",
            "",
            "remote-0000000000000000-11111111111111111111111111111111",
            "remote-0000000000000001-00000000000000000000000000000000",
            "remote-0000000000000001-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "remote-0000000000000001-1111111111111111111111111111111é",
        ] {
            assert!(namespace_fence(value).is_err(), "{value}");
        }
        assert_eq!(
            namespace_fence(&namespace(u64::MAX, [255; 16])).unwrap(),
            u64::MAX
        );
    }
}
