//! vault::crypto — envelope encryption for the Force One Vault.
//!
//! Key derivation: Argon2id (memory-hard, resistant to GPU/ASIC brute-force)
//! Encryption:      XChaCha20-Poly1305 (AEAD — confidentiality + integrity)
//!
//! Envelope format (bytes written to disk / passed to storage):
//!   [ salt (16 bytes) | nonce (24 bytes) | ciphertext (variable, includes 16-byte auth tag) ]

use argon2::{Argon2, Params, Version, Algorithm};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce, Key,
};

const SALT_LEN: usize = 16;

#[derive(Debug)]
pub enum CryptoError {
    KeyDerivation(String),
    Encryption(String),
    Decryption(String),
    InvalidEnvelope(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::KeyDerivation(e) => write!(f, "key derivation failed: {e}"),
            CryptoError::Encryption(e) => write!(f, "encryption failed: {e}"),
            CryptoError::Decryption(e) => write!(f, "decryption failed: {e}"),
            CryptoError::InvalidEnvelope(e) => write!(f, "invalid envelope: {e}"),
        }
    }
}
impl std::error::Error for CryptoError {}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let mut key_bytes = derive_key(passphrase, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let mut envelope = Vec::with_capacity(SALT_LEN + nonce.len() + ciphertext.len());
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    key_bytes.zeroize();Ok(envelope)
}

pub fn decrypt(envelope: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if envelope.len() < SALT_LEN + 24 {
        return Err(CryptoError::InvalidEnvelope(
            "envelope too short to contain salt + nonce".into(),
        ));
    }

    let salt = &envelope[..SALT_LEN];
    let nonce_bytes = &envelope[SALT_LEN..SALT_LEN + 24];
    let ciphertext = &envelope[SALT_LEN + 24..];

    let mut key_bytes = derive_key(passphrase, salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce_bytes);

    
    let result = cipher
    .decrypt(nonce, ciphertext)
    .map_err(|e| CryptoError::Decryption(e.to_string()));
key_bytes.zeroize();
result     
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let plaintext = b"vault secret payload";
        let passphrase = b"correct horse battery staple";

        let envelope = encrypt(plaintext, passphrase).expect("encrypt should succeed");
        let decrypted = decrypt(&envelope, passphrase).expect("decrypt should succeed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let plaintext = b"vault secret payload";
        let envelope = encrypt(plaintext, b"correct passphrase").expect("encrypt should succeed");

        let result = decrypt(&envelope, b"wrong passphrase");
        assert!(result.is_err());
    }
  }
