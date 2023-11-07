use serde::{Deserialize, Serialize};

use crate::package::vulnerabilities::{PackageVulnerability, TaggedPackageVulnerability};
use crate::purl::Purl;

pub mod dependencies;
pub mod vulnerabilities;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageTree {
    pub id: i32,
    pub purl: Purl,
    pub dependencies: Vec<PackageTree>,
}
impl PackageTree {
    pub fn merge_vulnerabilities(
        &self,
        vulns: &Vec<TaggedPackageVulnerability>,
    ) -> VulnerabilityTree {
        VulnerabilityTree {
            id: self.id,
            purl: self.purl.clone(),
            vulnerabilities: vulns
                .iter()
                .filter(|e| e.package_id == self.id)
                .map(|e| PackageVulnerability {
                    identifier: e.identifier.clone(),
                    scanner: e.scanner.clone(),
                    timestamp: e.timestamp,
                })
                .collect(),
            dependencies: self
                .dependencies
                .iter()
                .map(|e| e.merge_vulnerabilities(vulns).clone())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VulnerabilityTree {
    #[serde(skip)]
    id: i32,
    purl: Purl,
    vulnerabilities: Vec<PackageVulnerability>,
    dependencies: Vec<VulnerabilityTree>,
}
