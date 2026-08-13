//! vault::audit — hash-chained, tamper-evident audit log.
//!
//! Each entry's hash incorporates the previous entry's hash, forming
//! a chain. Any modification or deletion of a past entry breaks the
//! chain and is detectable via verify().

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: u64,
    pub actor: String,
    pub action: String,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl AuditLog {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    fn compute_hash(sequence: u64, timestamp: u64, actor: &str, action: &str, prev_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(actor.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(prev_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Appends a new entry to the chain, linked to the previous entry's hash.
    pub fn append(&mut self, actor: &str, action: &str) -> &AuditEntry {
        let sequence = self.entries.len() as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());

        let hash = Self::compute_hash(sequence, timestamp, actor, action, &prev_hash);

        self.entries.push(AuditEntry {
            sequence,
            timestamp,
            actor: actor.to_string(),
            action: action.to_string(),
            prev_hash,
            hash,
        });

        self.entries.last().unwrap()
    }

    /// Walks the entire chain, recomputing each hash and confirming
    /// it matches both the stored hash and the next entry's prev_hash.
    /// Returns Ok(()) if the chain is intact, or Err with the index
    /// of the first broken link.
    pub fn verify(&self) -> Result<(), usize> {
        let mut expected_prev = GENESIS_HASH.to_string();

        for (i, entry) in self.entries.iter().enumerate() {
            if entry.prev_hash != expected_prev {
                return Err(i);
            }
            let recomputed = Self::compute_hash(
                entry.sequence,
                entry.timestamp,
                &entry.actor,
                &entry.action,
                &entry.prev_hash,
            );
            if recomputed != entry.hash {
                return Err(i);
            }
            expected_prev = entry.hash.clone();
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies_when_untampered() {
        let mut log = AuditLog::new();
        log.append("alice", "vault.read");
        log.append("bob", "vault.write");
        log.append("alice", "vault.delete");

        assert!(log.verify().is_ok());
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn detects_tampered_entry() {
        let mut log = AuditLog::new();
        log.append("alice", "vault.read");
        log.append("bob", "vault.write");

        // Tamper with the first entry's action after the fact.
        log.entries[0].action = "vault.delete".to_string();

        assert_eq!(log.verify(), Err(0));
    }

    #[test]
    fn empty_log_verifies() {
        let log = AuditLog::new();
        assert!(log.verify().is_ok());
        assert!(log.is_empty());
    }
      }
