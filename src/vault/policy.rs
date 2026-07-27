use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
}

impl Principal {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    grants: Vec<(Principal, HashSet<Action>)>,
}

impl AccessPolicy {
    pub fn new() -> Self {
        Self { grants: Vec::new() }
    }

    pub fn grant(&mut self, principal: Principal, actions: &[Action]) {
        if let Some((_, existing)) = self.grants.iter_mut().find(|(p, _)| p == &principal) {
            existing.extend(actions.iter().cloned());
        } else {
            self.grants
                .push((principal, actions.iter().cloned().collect()));
        }
    }

    pub fn revoke(&mut self, principal: &Principal) {
        self.grants.retain(|(p, _)| p != principal);
    }

    pub fn authorize(&self, principal: &Principal, action: &Action) -> bool {
        self.grants
            .iter()
            .find(|(p, _)| p == principal)
            .map(|(_, actions)| actions.contains(action))
            .unwrap_or(false)
    }
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self::new()
    }
}
