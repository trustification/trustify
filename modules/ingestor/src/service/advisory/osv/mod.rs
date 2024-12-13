mod prefix;

pub mod loader;
pub mod translate;

use crate::service::Error;
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

/// Parse an OSV document into a [`Vulnerability`].
pub fn parse(buffer: &[u8]) -> Result<Vulnerability, Error> {
    let osv: Vulnerability = serde_json::from_slice(buffer)
        .map_err(Error::from)
        .or_else(|_| from_yaml(buffer).map_err(Error::from))?;

    Ok(osv)
}
