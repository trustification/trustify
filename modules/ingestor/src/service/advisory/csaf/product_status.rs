use super::util::branch_purl;
use crate::graph::advisory::advisory_vulnerability::{Version, VersionInfo, VersionSpec};
use cpe::cpe::Cpe;
use csaf::definitions::{Branch, BranchCategory, FullProductName};
use trustify_common::purl::Purl;
use trustify_entity::version_scheme::VersionScheme;

#[derive(Clone, Default, Debug, Eq, Hash, PartialEq)]
pub struct ProductStatus {
    pub vendor: Option<String>,
    pub product: String,
    pub version: Option<VersionInfo>,
    pub cpe: Option<trustify_common::cpe::Cpe>,
    pub status: &'static str,
    pub packages: Vec<Purl>,
}

impl ProductStatus {
    // Method to update ProductStatus from a branch
    pub fn update_from_branch(&mut self, branch: &Branch) {
        match branch.category {
            // Get product related info
            BranchCategory::ProductName => {
                self.product = branch.name.clone();
                self.set_version(branch.product.clone());
            }
            // Get organisation info
            BranchCategory::Vendor => {
                self.vendor = Some(branch.name.clone());
            }
            // Get component/package info
            BranchCategory::ProductVersion => {
                let purl = match branch.product.clone() {
                    Some(full_name) => match full_name.product_identification_helper {
                        Some(id_helper) => match id_helper.purl {
                            Some(purl) => Purl::from(purl),
                            None => ProductStatus::generic_purl(&branch.name),
                        },
                        None => ProductStatus::generic_purl(&full_name.product_id.0),
                    },
                    None => ProductStatus::generic_purl(&branch.name),
                };
                self.packages.push(purl);
            }
            // For everything else, for now see if we can get any purls
            _ => {
                if let Some(purl) = branch_purl(branch) {
                    let purl = Purl::from(purl.clone());
                    self.packages.push(purl);
                }
            }
        }
    }

    /// Parse purl from generic identifiers
    fn generic_purl(name: &str) -> Purl {
        // try to extract at least name and optionally namespace
        // usually separate by /
        // e.g. io.quarkus/quarkus-vertx-http
        let parts = name.split('/').collect::<Vec<_>>();

        let (namespace, name) = if parts.len() >= 2 {
            (Some(parts[0]), parts[1])
        } else {
            (None, parts[0])
        };

        Purl {
            ty: "generic".to_string(),
            namespace: namespace.map(|s| s.to_string()),
            name: name.to_string(),
            version: None,
            qualifiers: Default::default(),
        }
    }

    /// Parse cpe or purl from product identifier helper
    pub fn set_version(&mut self, full_name: Option<FullProductName>) {
        self.version = full_name.and_then(|full_name| {
            full_name.product_identification_helper.and_then(|id| {
                id.cpe
                    .map(|cpe| {
                        // We have a CPE in product identifier helper
                        self.cpe = Some(cpe.clone().into());
                        let version = cpe.version().to_string();
                        if version != "*" {
                            // Lenient semver parsing so we can get "product streams", e.g.
                            // 2 is > 2.0.0
                            // 2.13 is > 2.13.0
                            match lenient_semver::parse(version.as_str()).map_err(|e| e.owned()) {
                                Ok(semver) => VersionInfo {
                                    spec: VersionSpec::Range(
                                        Version::Inclusive(semver.to_string()),
                                        Version::Unbounded,
                                    ),
                                    scheme: VersionScheme::Semver,
                                },
                                Err(_) => VersionInfo {
                                    spec: VersionSpec::Exact(version),
                                    scheme: VersionScheme::Generic,
                                },
                            }
                        } else {
                            // Treat * value as unbounded version
                            VersionInfo {
                                spec: VersionSpec::Range(Version::Unbounded, Version::Unbounded),
                                scheme: VersionScheme::Semver,
                            }
                        }
                    })
                    .or_else(|| {
                        id.purl.and_then(|purl| {
                            // If we have purl, use an exact version
                            purl.version().map(|version| VersionInfo {
                                spec: VersionSpec::Exact(version.to_string()),
                                scheme: VersionScheme::Semver,
                            })
                        })
                    })
            })
        });
    }
}
