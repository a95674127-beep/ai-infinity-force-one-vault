use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum VaultCryptoError {
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed — wrong passphrase or the data was tampered with")]
    Decryption,
    #[error("action not authorized by policy")]
    NotAuthorized,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedBlob {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct VaultCipher;

impl VaultCipher {
    fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], VaultCryptoError> {
        let params = Params::new(19_456, 2, 1, Some(KEY_LEN))
            .map_err(|e| VaultCryptoError::KeyDerivation(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; KEY_LEN];
        argon2
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| VaultCryptoError::KeyDerivation(e.to_string()))?;
        Ok(key)
    }

    pub fn encrypt(passphrase: &str, plaintext: &[u8]) -> Result<EncryptedBlob, VaultCryptoError> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let mut key = Self::derive_key(passphrase.as_bytes(), &salt)?;
        let cipher = XChaCha20Poly1305::new(key.as_slice().into());

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| VaultCryptoError::Encryption)?;

        key.zeroize();

        Ok(EncryptedBlob {
            salt: salt.to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    pub fn decrypt(passphrase: &str, blob: &EncryptedBlob) -> Result<Vec<u8>, VaultCryptoError> {
        let mut key = Self::derive_key(passphrase.as_bytes(), &blob.salt)?;
        let cipher = XChaCha20Poly1305::new(key.as_slice().into());
        let nonce = XNonce::from_slice(&blob.nonce);

        let plaintext = cipher
            .decrypt(nonce, blob.ciphertext.as_ref())
            .map_err(|_| VaultCryptoError::Decryption)?;

        key.zeroize();
        Ok(plaintext)
    }
  }
