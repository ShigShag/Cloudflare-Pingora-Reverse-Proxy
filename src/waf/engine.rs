use pingora::prelude::*;

use super::rule::{SecurityRule, SecurityViolation};

pub struct WafEngine {
    rules: Vec<Box<dyn SecurityRule>>,
}

impl WafEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: Box<dyn SecurityRule>) {
        self.rules.push(rule);
    }

    /// Run header-phase checks across all enabled rules.
    pub fn check_headers(&self, req: &RequestHeader) -> Vec<SecurityViolation> {
        let mut violations = Vec::new();
        for rule in &self.rules {
            if rule.enabled() {
                violations.extend(rule.check_headers(req));
            }
        }
        violations
    }

    /// Run body-phase checks across all enabled rules.
    pub fn check_body(&self, body: &[u8]) -> Vec<SecurityViolation> {
        let mut violations = Vec::new();
        for rule in &self.rules {
            if rule.enabled() {
                violations.extend(rule.check_body(body));
            }
        }
        violations
    }
}
