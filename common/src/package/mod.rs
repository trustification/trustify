use serde::{Deserialize, Serialize};

use crate::purl::Purl;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VulnerabilityAssertions {
    pub assertions: Vec<Assertion>,
}

impl VulnerabilityAssertions {
    pub fn affected_claimants(&self) -> Vec<Claimant> {
        self.assertions
            .iter()
            .flat_map(|e| {
                if let Assertion::Affected(claimant) = e {
                    Some(claimant.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Assertion {
    Affected(Claimant),
    NotAffected(Claimant),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claimant {
    pub identifier: String,
    pub location: String,
    pub sha256: String,
}
