use std::collections::BTreeMap;
use trustify_module_ingestor::service::Format;

/// Information extracted from an SBOM
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct ExtractResult {
    /// the actual, concrete format
    pub format: Format,
    /// packages of the SBOM
    pub packages: BTreeMap<String, ExtractPackage>,
}

/// Information extracted from a package
#[derive(
    Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize, utoipa::ToSchema,
)]
pub struct ExtractPackage {
    /// PURLs found as alias for this package
    pub purls: Vec<String>,
}
