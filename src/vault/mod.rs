//! vault — Force One Vault module root.
//!
//! Ties together the vault's subsystems: crypto (encryption),
//! policy (access control), and audit (tamper-evident logging).

pub mod crypto;
pub mod policy;
pub mod audit;

use policy::{AccessPolicy, Action, Decision, Principal, Resource};
use audit::AuditLog;

/// The Force One Vault: combines encrypted storage, access policy
/// enforcement, and a tamper-evident audit trail into one interface.
pub struct Vault {
    policy: AccessPolicy,
    audit: AuditLog,
}

#[derive(Debug)]
pub enum VaultError {
    AccessDenied,
    Crypto(crypto::CryptoError),
}

impl Vault {
    pub fn new() -> Self {
        Self {
            policy: AccessPolicy::new(),
            audit: AuditLog::new(),
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
        self.audit.append(&principal.0, &format!("store:{}", resource.0));

        match decision {
            Decision::Deny => Err(VaultError::AccessDenied),
            Decision::Allow => {
                crypto::encrypt(plaintext, passphrase).map_err(VaultError::Crypto)
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
        self.audit.append(&principal.0, &format!("retrieve:{}", resource.0));

        match decision {
            Decision::Deny => Err(VaultError::AccessDenied),
            Decision::Allow => {
                crypto::decrypt(envelope, passphrase).map_err(VaultError::Crypto)
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
        }
