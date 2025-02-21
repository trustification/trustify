use sea_orm::FromQueryResult;
use trustify_entity::qualified_purl::CanonicalPurl;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct SbomPackageLicense {
    pub name: String,
    pub group: Option<String>,
    pub version: Option<String>,
    /// package package URL
    pub purl: Vec<Purl>,
    pub cpe: Vec<trustify_entity::cpe::Model>,
    /// List of all package license
    pub license_text: Option<String>,
}

#[derive(Debug, Clone, FromQueryResult)]
pub struct Sbom {
    pub sbom_id: Uuid,
    pub node_id: String,
    pub sbom_namespace: String,
}

#[derive(Debug, Clone, FromQueryResult)]
pub struct Purl {
    pub purl: CanonicalPurl,
}

#[derive(Debug, Clone, FromQueryResult)]
pub struct SbomPackageLicenseBase {
    pub node_id: String,
    pub sbom_id: Uuid,
    pub name: String,
    pub group: Option<String>,
    pub version: Option<String>,
    pub license_text: Option<String>,
}

#[derive(Debug, Clone, Default, FromQueryResult)]
pub struct SbomNameId {
    pub sbom_name: String,
    pub sbom_id: String,
}

#[derive(Debug, Clone, FromQueryResult)]
pub struct ExtractedLicensingInfos {
    pub license_id: String,
    pub name: String,
    pub extracted_text: String,
    pub comment: String,
}
