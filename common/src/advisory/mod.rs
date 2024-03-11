use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdvisoryVulnerabilityAssertions {
    pub assertions: HashMap<String, Vec<Assertion>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Assertion {
    Affected {
        vulnerability: String,
        start_version: String,
        end_version: String,
    },
    NotAffected {
        vulnerability: String,
        version: String,
    },
    Fixed {
        vulnerability: String,
        version: String,
    },
}
