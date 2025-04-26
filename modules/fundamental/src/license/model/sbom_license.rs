use sea_orm::FromQueryResult;
use trustify_entity::{
    labels::Labels, qualified_purl::CanonicalPurl, sbom_package_license::LicenseCategory,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SbomPackageLicense {
    pub name: String,
    pub group: Option<String>,
    pub version: Option<String>,
    /// package package URL
    pub purl: Vec<Purl>,
    pub cpe: Vec<trustify_entity::cpe::Model>,
    /// List of all package license
    pub license_declared_text: Option<String>,
    pub license_concluded_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, FromQueryResult)]
pub struct Sbom {
    pub sbom_id: Uuid,
    pub node_id: String,
    pub sbom_namespace: String,
}

#[derive(Debug, Clone, PartialEq, FromQueryResult)]
pub struct Purl {
    pub purl: CanonicalPurl,
}

#[derive(Debug, Clone, PartialEq, FromQueryResult)]
pub struct SbomPackageLicenseBase {
    pub node_id: String,
    pub sbom_id: Uuid,
    pub name: String,
    pub group: Option<String>,
    pub version: Option<String>,
    pub license_text: Option<String>,
    pub license_type: Option<LicenseCategory>,
}

#[derive(Debug, Clone, Default, PartialEq, FromQueryResult)]
pub struct SbomNameId {
    pub sbom_name: String,
    pub sbom_id: String,
    pub labels: Labels,
}

#[derive(Debug, Clone, PartialEq, FromQueryResult)]
pub struct ExtractedLicensingInfos {
    pub license_id: String,
    pub name: String,
    pub extracted_text: String,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MergedSbomPackageLicense {
    pub node_id: String,
    pub sbom_id: Uuid,
    pub name: String,
    pub group: Option<String>,
    pub version: Option<String>,
    pub license_declared_text: Option<String>,
    pub license_concluded_text: Option<String>,
}

impl MergedSbomPackageLicense {
    pub fn apply_license(&mut self, license: &SbomPackageLicenseBase) {
        if let Some(license_type) = &license.license_type {
            match license_type {
                LicenseCategory::Declared => {
                    self.license_declared_text = license.license_text.clone();
                }
                LicenseCategory::Concluded => {
                    self.license_concluded_text = license.license_text.clone();
                }
            }
        }
    }
}
