//! Core crypto data types: context, units, capabilities (SPEC §15–16).

use uuid::Uuid;

use crate::secret::SecretBuffer;

/// Context bound to every batch operation. For providers with context-binding
/// capability, ciphertext is cryptographically tied to these values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoContext {
    pub volume_uuid: Uuid,
    pub format_version: u32,
    pub crypto_compatibility_id: String,
}

/// One plaintext crypto unit, addressed by its unit index.
#[derive(Debug)]
pub struct PlaintextUnit {
    pub unit_index: u64,
    pub data: SecretBuffer,
}

/// One ciphertext crypto unit, addressed by its unit index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextUnit {
    pub unit_index: u64,
    pub data: Vec<u8>,
}

/// A security capability the provider may or may not deliver.
///
/// SPEC §16: "If a provider cannot prove or contractually guarantee a security
/// capability, Maki MUST treat that capability as absent."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Capability {
    /// Not provided, or provided but not provable — treated identically.
    #[default]
    Absent,
    /// Contractually guaranteed by the provider profile.
    Contractual,
    /// Verified by Maki itself (e.g. local AEAD).
    Verified,
}

impl Capability {
    pub fn present(self) -> bool {
        !matches!(self, Capability::Absent)
    }

    /// The weaker of two claims: what only one of two interchangeable
    /// providers delivers is not delivered by a set containing both.
    pub fn weakest(self, other: Capability) -> Capability {
        fn rank(c: Capability) -> u8 {
            match c {
                Capability::Absent => 0,
                Capability::Contractual => 1,
                Capability::Verified => 2,
            }
        }
        if rank(other) < rank(self) {
            other
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCapability {
    pub supported: bool,
    /// Maximum items per batch (1 if batching unsupported).
    pub max_items: u32,
    /// Maximum total plaintext bytes per batch.
    pub max_bytes: u64,
}

impl Default for BatchCapability {
    fn default() -> Self {
        Self {
            supported: false,
            max_items: 1,
            max_bytes: u64::MAX,
        }
    }
}

/// The storage-related contract of a provider (SPEC §1, §16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoCapabilities {
    pub provider_id: String,
    /// Two providers are ciphertext-interchangeable iff this matches.
    pub crypto_compatibility_id: String,
    /// Plaintext sizes (bytes) the provider accepts. Must include the volume's
    /// crypto_unit_size.
    pub supported_plaintext_sizes: Vec<u32>,
    /// Maximum ciphertext bytes produced per unit.
    pub max_ciphertext_size: u32,
    pub stateless: bool,
    pub retry_safe: bool,
    pub batch: BatchCapability,
    pub integrity: Capability,
    pub context_binding: Capability,
    pub replay_protection: Capability,
}

impl CryptoCapabilities {
    /// The contract a set of interchangeable providers can honour as a whole:
    /// a batch built against it may be routed to any member, so batch limits
    /// are the minimum, accepted plaintext sizes the intersection, the
    /// ciphertext bound the maximum any member produces, and every security
    /// claim the weakest one (SPEC §16: a capability the set cannot
    /// guarantee is `Absent`). Identity fields are taken from `self`.
    pub fn intersect(self, other: &CryptoCapabilities) -> CryptoCapabilities {
        CryptoCapabilities {
            provider_id: self.provider_id,
            crypto_compatibility_id: self.crypto_compatibility_id,
            supported_plaintext_sizes: self
                .supported_plaintext_sizes
                .into_iter()
                .filter(|size| other.supported_plaintext_sizes.contains(size))
                .collect(),
            max_ciphertext_size: self.max_ciphertext_size.max(other.max_ciphertext_size),
            stateless: self.stateless && other.stateless,
            retry_safe: self.retry_safe && other.retry_safe,
            batch: BatchCapability {
                supported: self.batch.supported && other.batch.supported,
                max_items: self.batch.max_items.min(other.batch.max_items),
                max_bytes: self.batch.max_bytes.min(other.batch.max_bytes),
            },
            integrity: self.integrity.weakest(other.integrity),
            context_binding: self.context_binding.weakest(other.context_binding),
            replay_protection: self.replay_protection.weakest(other.replay_protection),
        }
    }

    /// True if `plaintext_len` is an accepted plaintext size.
    pub fn accepts_plaintext_size(&self, plaintext_len: usize) -> bool {
        u32::try_from(plaintext_len)
            .map(|len| self.supported_plaintext_sizes.contains(&len))
            .unwrap_or(false)
    }
}
