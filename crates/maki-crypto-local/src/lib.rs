//! `maki-crypto-local` — local crypto providers (SPEC §17).
//!
//! - `AesGcmSivProvider`: AES-256-GCM-SIV, authenticated, context-bound via
//!   AAD (volume UUID, crypto unit index, format version, compatibility ID).
//! - `AesXtsProvider`: AES-256-XTS, length-preserving, position-tweaked.
//!   **Provides no authenticated integrity** — corruption is only caught by
//!   the volume layer's slot CRCs, and a forged ciphertext of correct length
//!   decrypts to garbage without error. Use GCM-SIV unless XTS is required.

pub mod gcm_siv;
pub mod keysource;
pub mod xts;

pub use gcm_siv::AesGcmSivProvider;
pub use xts::AesXtsProvider;
