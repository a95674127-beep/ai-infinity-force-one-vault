use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::policy::{Action, Principal};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub principal: Principal,
    pub action: Action,
    pub resource: String,
    pub allowed: bool,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Default)]
pub struct AuditLog {
    events: Vec<AuditEvent>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    fn last_hash(&self) -> String {
        self.events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string())
    }

    fn compute_hash(
        prev_hash: &str,
        timestamp: &DateTime<Utc>,
        principal: &Principal,
        action: &Action,
        resource: &str,
        allowed: bool,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(principal.id.as_bytes());
        hasher.update(format!("{:?}", action).as_bytes());
        hasher.update(resource.as_bytes());
        hasher.update([allowed as u8]);
        format!("{:x}", hasher.finalize())
    }

    pub fn record(
        &mut self,
        principal: Principal,
        action: Action,
        resource: impl Into<String>,
        allowed: bool,
    ) -> &AuditEvent {
        let prev_hash = self.last_hash();
        let timestamp = Utc::now();
        let resource = resource.into();
        let hash = Self::compute_hash(&prev_hash, &timestamp, &principal, &action, &resource, allowed);

        self.events.push(AuditEvent {
            timestamp,
            principal,
            action,
            resource,
            allowed,
            prev_hash,
            hash,
        });
