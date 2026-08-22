//! vault — Force One Vault module root.
//!
//! Ties together the vault's subsystems: crypto (encryption),
//! policy (access control), and audit (tamper-evident logging).

pub mod crypto;
pub mod policy;
pub mod audit;

use policy::{AccessPolicy, Action, Decision, Principal, Resource};
use audit::AuditLog;
use crate::detection::hash_blocklist::{HashBlocklist, BlocklistVerdict};
use crate::detection::entropy_scan::{self, EntropyVerdict};

/// The Force One Vault: combines encrypted storage, access policy
/// enforcement, and a tamper-evident audit trail into one interface.
pub struct Vault {
    policy: AccessPolicy,
    audit: AuditLog,
    blocklist: HashBlocklist,
}

#[derive(Debug)]
pub enum VaultError {
    AccessDenied,
    Crypto(crypto::CryptoError),
    DetectionBlocked(String),
}

impl Vault {
    pub fn new() -> Self {
const KNOWN_BAD_HASHES: &str = include_str!("../detection/known_bad_hashes.txt");
        let blocklist = HashBlocklist::load_from_str(KNOWN_BAD_HASHES);

        Self {
            policy: AccessPolicy::new(),
            audit: AuditLog::new(),
            blocklist,
        }
    }

    pub fn grant(&mut self, rule: policy::Rule) {
        self.policy.grant(rule);
    }

    pub fn store(
        &mut self,
        principal: &Principal,
        resource: &Resource,
        plaintext: &[u8],
        passphrase: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let decision = self.policy.evaluate(principal, resource, Action::Write);

        if decision == Decision::Deny {
            self.audit.append(&principal.0, &format!("store.denied:{}", resource.0));
            return Err(VaultError::AccessDenied);
        }

        match self.blocklist.scan_payload(plaintext) {
            BlocklistVerdict::Match(hash) => {
                self.audit.append(&principal.0, &format!("store.blocked_hash:{}", hash));
                return Err(VaultError::DetectionBlocked(format!("known-bad hash: {}", hash)));
            }
            BlocklistVerdict::Error(e) => {
                self.audit.append(&principal.0, &format!("store.scan_error:{}", e));
                return Err(VaultError::DetectionBlocked(format!("scan error: {}", e)));
            }
            BlocklistVerdict::Clean => {}
        }

        if let EntropyVerdict::Suspicious(score) = entropy_scan::scan_payload(plaintext) {
            self.audit.append(&principal.0, &format!("store.blocked_entropy:{:.2}", score));
            return Err(VaultError::DetectionBlocked(format!("suspicious entropy: {:.2}", score)));
        }

        match crypto::encrypt(plaintext, passphrase) {
            Ok(envelope) => {
                self.audit.append(&principal.0, &format!("store.success:{}", resource.0));
                Ok(envelope)
            }
            Err(e) => {
                self.audit.append(&principal.0, &format!("store.crypto_failed:{}", resource.0));
                Err(VaultError::Crypto(e))
            }
        }
    }

    pub fn retrieve(
        &mut self,
        principal: &Principal,
        resource: &Resource,
        envelope: &[u8],
        passphrase: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let decision = self.policy.evaluate(principal, resource, Action::Read);

        if decision == Decision::Deny {
            self.audit.append(&principal.0, &format!("retrieve.denied:{}", resource.0));
            return Err(VaultError::AccessDenied);
        }

        match crypto::decrypt(envelope, passphrase) {
            Ok(plaintext) => {
                self.audit.append(&principal.0, &format!("retrieve.success:{}", resource.0));
                Ok(plaintext)
            }
            Err(e) => {
                self.audit.append(&principal.0, &format!("retrieve.crypto_failed:{}", resource.0));
                Err(VaultError::Crypto(e))
            }
        }
    }

    pub fn verify_audit(&self) -> Result<(), usize> {
        self.audit.verify()
    }

    pub fn audit_len(&self) -> usize {
        self.audit.len()
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_store_without_grant() {
        let mut vault = Vault::new();
        let alice = Principal("alice".into());
        let secret = Resource("secret1".into());

        let result = vault.store(&alice, &secret, b"top secret", b"pw");
        assert!(matches!(result, Err(VaultError::AccessDenied)));
        assert_eq!(vault.audit_len(), 1);
    }

    #[test]
    fn allows_store_and_retrieve_with_grant() {
        let mut vault = Vault::new();
        let alice = Principal("alice".into());
        let secret = Resource("secret1".into());

        vault.grant(policy::Rule {
            principal: alice.clone(),
            resource: secret.clone(),
            actions: vec![Action::Write, Action::Read],
        });

        let ciphertext = vault.store(&alice, &secret, b"hello vault", b"passphrase").unwrap();
        let plaintext = vault.retrieve(&alice, &secret, &ciphertext, b"passphrase").unwrap();

        assert_eq!(plaintext, b"hello vault");
    }
#[test]
    fn rejects_store_with_blocklisted_payload() {
        let mut vault = Vault::new();
        let alice = Principal("alice".into());
        let secret = Resource("secret1".into());

        vault.grant(policy::Rule {
            principal: alice.clone(),
            resource: secret.clone(),
            actions: vec![Action::Write, Action::Read],
        });

        let result = vault.store(&alice, &secret, b"malicious_test_payload", b"pass");
        assert!(matches!(result, Err(VaultError::DetectionBlocked(_))));
        assert_eq!(vault.audit_len(), 1);
    }
}
