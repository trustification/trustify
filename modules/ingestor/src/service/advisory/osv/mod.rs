pub mod loader;
pub mod translate;

use osv::schema::Vulnerability;

/// Load a [`Vulnerability`] from YAML, using the "classic" enum representation.
pub fn from_yaml(data: &[u8]) -> Result<Vulnerability, serde_yml::Error> {
    #[derive(serde::Deserialize)]
    struct VulnerabilityWrapped(
        #[serde(with = "serde_yml::with::singleton_map_recursive")] Vulnerability,
    );

    serde_yml::from_slice::<VulnerabilityWrapped>(data).map(|osv| osv.0)
}

/// Serialize a [`Vulnerability`] as YAML, using the "classic" enum representation.
pub fn to_yaml(vuln: &Vulnerability) -> Result<String, serde_yml::Error> {
    #[derive(serde::Serialize)]
    struct VulnerabilityWrapped<'a>(
        #[serde(with = "serde_yml::with::singleton_map_recursive")] &'a Vulnerability,
    );

    serde_yml::to_string(&VulnerabilityWrapped(vuln))
}
