//! AI Infinity Force One — zero-trust vault core.
//!
//! Three pieces, deliberately kept separate so each can be reasoned about
//! (and audited) on its own:
//!
//! - [`vault::crypto`] — Argon2id key derivation + XChaCha20-Poly1305
//!   authenticated encryption for secrets at rest.
//! - [`vault::policy`] — deny-by-default access control: nothing is
//!   permitted unless explicitly granted.
//! - [`vault::audit`]  — a hash-chained, tamper-evident log of every
//!   access decision (allowed or denied).
//!
//! [`Vault`] wires the three together so a caller never touches raw
//! ciphertext without going through a policy check that gets logged.

pub mod vault;

pub use vault::audit::{AuditEvent, AuditLog};
pub use vault::crypto::{EncryptedBlob, VaultCipher, VaultCryptoError};
pub use vault::policy::{AccessPolicy, Action, Principal};
pub use vault::Vault;
