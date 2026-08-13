//! vault::policy — deny-by-default access control.
//!
//! Every request must be explicitly granted by a matching rule.
//! Absence of a rule, or any ambiguity, resolves to Deny.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Resource(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Delete,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub principal: Principal,
    pub resource: Resource,
    pub actions: Vec<Action>,
}

#[derive(Debug, Default)]
pub struct AccessPolicy {
    rules: HashMap<(Principal, Resource), Vec<Action>>,
}

impl AccessPolicy {
    pub fn new() -> Self {
        Self { rules: HashMap::new() }
    }

    pub fn grant(&mut self, rule: Rule) {
        self.rules
            .entry((rule.principal, rule.resource))
            .or_insert_with(Vec::new)
            .extend(rule.actions);
    }

    pub fn evaluate(&self, principal: &Principal, resource: &Resource, action: Action) -> Decision {
        match self.rules.get(&(principal.clone(), resource.clone())) {
            Some(actions) if actions.contains(&action) => Decision::Allow,
            _ => Decision::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_by_default() {
        let policy = AccessPolicy::new();
        let principal = Principal("alice".into());
        let resource = Resource("vault/secret1".into());

        assert_eq!(policy.evaluate(&principal, &resource, Action::Read), Decision::Deny);
    }

    #[test]
    fn allows_explicit_grant() {
        let mut policy = AccessPolicy::new();
        let principal = Principal("alice".into());
        let resource = Resource("vault/secret1".into());

        policy.grant(Rule {
            principal: principal.clone(),
            resource: resource.clone(),
            actions: vec![Action::Read],
        });

        assert_eq!(policy.evaluate(&principal, &resource, Action::Read), Decision::Allow);
        assert_eq!(policy.evaluate(&principal, &resource, Action::Write), Decision::Deny);
    }

    #[test]
    fn denies_unrelated_principal() {
        let mut policy = AccessPolicy::new();
        let alice = Principal("alice".into());
        let bob = Principal("bob".into());
        let resource = Resource("vault/secret1".into());

        policy.grant(Rule {
            principal: alice,
            resource: resource.clone(),
            actions: vec![Action::Read],
        });

        assert_eq!(policy.evaluate(&bob, &resource, Action::Read), Decision::Deny);
    }
          }
