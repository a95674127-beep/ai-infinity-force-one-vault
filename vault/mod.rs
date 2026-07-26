pub mod audit;
pub mod crypto;
pub mod policy;

use audit::AuditLog;
use crypto::{EncryptedBlob, VaultCipher, VaultCryptoError};
use policy::{AccessPolicy, Action, Principal};

/// Ties encryption, access policy, and audit logging into one unit so that
/// no secret can be read or written without an authorization check that is
/// itself recorded — allowed or denied.
pub struct Vault {
    policy: AccessPolicy,
    audit: AuditLog,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            policy: AccessPolicy::new(),
            audit: AuditLog::new(),
        }
    }

    pub fn grant(&mut self, principal: Principal, actions: &[Action]) {
        self.policy.grant(principal, actions);
    }

    pub fn revoke(&mut self, principal: &Principal) {
        self.policy.revoke(principal);
    }

    pub fn put_secret(
        &mut self,
        principal: &Principal,
        passphrase: &str,
        resource: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedBlob, VaultCryptoError> {
        let allowed = self.policy.authorize(principal, &Action::Write);
        self.audit
            .record(principal.clone(), Action::Write, resource, allowed);
        if !allowed {
            return Err(VaultCryptoError::NotAuthorized);
        }
        VaultCipher::encrypt(passphrase, plaintext)
    }

    pub fn get_secret(
        &mut self,
        principal: &Principal,
        passphrase: &str,
        resource: &str,
        blob: &EncryptedBlob,
    ) -> Result<Vec<u8>, VaultCryptoError> {
        let allowed = self.policy.authorize(principal, &Action::Read);
        self.audit
            .record(principal.clone(), Action::Read, resource, allowed);
        if !allowed {
            return Err(VaultCryptoError::NotAuthorized);
        }
        VaultCipher::decrypt(passphrase, blob)
    }

    pub fn audit_log(&self) -> &AuditLog {
        &self.audit
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
      }
