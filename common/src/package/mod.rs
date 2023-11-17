use serde::{Deserialize, Serialize};

use crate::purl::Purl;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PackageVulnerabilityAssertions {
    pub assertions: Vec<Assertion>,
}

impl PackageVulnerabilityAssertions {
    pub fn affected_claimants(&self) -> Vec<Claimant> {
        self.assertions
            .iter()
            .flat_map(|e| {
                if let Assertion::Affected { claimant, .. } = e {
                    Some(claimant.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn not_affected_claimants(&self) -> Vec<Claimant> {
        self.assertions
            .iter()
            .flat_map(|e| {
                if let Assertion::NotAffected { claimant, .. } = e {
                    Some(claimant.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn not_affected_claimants_for_version(
        &self,
        candidate_version: &str,
    ) -> Result<Vec<Claimant>, lenient_semver::parser::OwnedError> {
        let candidate_semver = lenient_semver::parse(candidate_version).map_err(|e| e.owned())?;

        let mut claimants = Vec::new();
        for assertion in &self.assertions {
            if let Assertion::NotAffected { claimant, version, .. } = assertion {
                let version = lenient_semver::parse(version).map_err(|e| e.owned())?;

                if version == candidate_semver {
                    claimants.push(claimant.clone());
                }
            }
        }

        Ok(claimants)
    }

    pub fn affected_claimants_for_version(
        &self,
        candidate_version: &str,
    ) -> Result<Vec<Claimant>, lenient_semver::parser::OwnedError> {
        let candidate_semver = lenient_semver::parse(candidate_version).map_err(|e| e.owned())?;

        let mut claimants = Vec::new();

        for assertion in &self.assertions {
            if let Assertion::Affected {
                claimant,
                start_version,
                end_version,
                ..
            } = assertion
            {
                let start_version = lenient_semver::parse(start_version).map_err(|e| e.owned())?;
                let end_version = lenient_semver::parse(end_version).map_err(|e| e.owned())?;

                if candidate_semver >= start_version && candidate_semver < end_version {
                    claimants.push(claimant.clone())
                }
            }
        }

        let not_affected_for_version =
            self.not_affected_claimants_for_version(candidate_version)?;

        let claimants = claimants
            .drain(0..)
            .filter(|each| {
                !not_affected_for_version.iter().any(|not_affected| {
                    each.sha256 == not_affected.sha256
                        && each.location == not_affected.location
                        && each.identifier == not_affected.identifier
                })
            })
            .collect();

        Ok(claimants)
    }

    pub fn filter_by_version(
        &self,
        version: &str,
    ) -> Result<Self, lenient_semver::parser::OwnedError> {
        let semver = lenient_semver::parse(version).map_err(|e| e.owned())?;

        let mut filtered_assertions = vec![];

        for assertion in &self.assertions {
            match assertion {
                affected @ Assertion::Affected {
                    start_version,
                    end_version,
                    ..
                } => {
                    let affected_start_semver =
                        lenient_semver::parse(start_version).map_err(|e| e.owned())?;
                    let affected_end_semver =
                        lenient_semver::parse(end_version).map_err(|e| e.owned())?;

                    if semver >= affected_start_semver && semver < affected_end_semver {
                        filtered_assertions.push(affected.clone());
                    }
                }
                not_affected @ Assertion::NotAffected { version, .. } => {
                    let not_affected_semver =
                        lenient_semver::parse(version).map_err(|e| e.owned())?;

                    if not_affected_semver == semver {
                        filtered_assertions.push(not_affected.clone())
                    }
                }
            }
        }

        Ok(PackageVulnerabilityAssertions {
            assertions: filtered_assertions,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Assertion {
    Affected {
        vulnerabilities: Vec<String>,
        claimant: Claimant,
        start_version: String,
        end_version: String,
    },
    NotAffected {
        vulnerabilities: Vec<String>,
        claimant: Claimant,
        version: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claimant {
    pub identifier: String,
    pub location: String,
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use crate::package::{Assertion, Claimant, PackageVulnerabilityAssertions};

    #[test]
    fn not_affected() {
        let assertions = PackageVulnerabilityAssertions {
            assertions: vec![
                Assertion::Affected {
                    vulnerabilities: vec![ "CVE-123".to_string()],
                    claimant: Claimant {
                        identifier: "rhsa-1".to_string(),
                        location: "here".to_string(),
                        sha256: "1".to_string(),
                    },
                    start_version: "0".to_string(),
                    end_version: "2".to_string(),
                },
                Assertion::NotAffected {
                    vulnerabilities: vec![ "CVE-123".to_string()],
                    claimant: Claimant {
                        identifier: "rhsa-1".to_string(),
                        location: "here".to_string(),
                        sha256: "1".to_string(),
                    },
                    version: "1.2.0".to_string(),
                },
                Assertion::NotAffected {
                    vulnerabilities: vec![ "CVE-123".to_string()],
                    claimant: Claimant {
                        identifier: "ghsa-1".to_string(),
                        location: "there".to_string(),
                        sha256: "1".to_string(),
                    },
                    version: "1.2".to_string(),
                },
                Assertion::NotAffected {
                    vulnerabilities: vec![ "CVE-123".to_string()],
                    claimant: Claimant {
                        identifier: "ghsa-1".to_string(),
                        location: "there".to_string(),
                        sha256: "1".to_string(),
                    },
                    version: "1.2.3".to_string(),
                },
            ],
        };

        let claimants = assertions
            .not_affected_claimants_for_version("1.2")
            .unwrap();

        assert_eq!(2, claimants.len());

        let claimants = assertions.affected_claimants_for_version("1.2").unwrap();
        assert_eq!(0, claimants.len());

        let claimants = assertions.affected_claimants_for_version("1.3").unwrap();
        assert_eq!(1, claimants.len());
    }
}
