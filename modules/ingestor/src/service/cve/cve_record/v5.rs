use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CveRecord {
    pub data_type: String,
    pub data_version: String,
    pub cve_metadata: CveMetadata,
    pub containers: Containers,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "state", rename_all = "UPPERCASE")]
pub enum CveMetadata {
    Published(MetadataPublished),
    Rejected(MetadataRejected),
}

impl CveMetadata {
    pub fn cve_id(&self) -> &str {
        match self {
            CveMetadata::Published(inner) => &inner.cve_id,
            CveMetadata::Rejected(inner) => &inner.cve_id,
        }
    }

    pub fn date_reserved(&self) -> Option<OffsetDateTime> {
        match self {
            CveMetadata::Published(inner) => inner.date_reserved,
            CveMetadata::Rejected(inner) => inner.date_reserved,
        }
    }

    pub fn date_published(&self) -> Option<OffsetDateTime> {
        match self {
            CveMetadata::Published(inner) => inner.date_published,
            CveMetadata::Rejected(inner) => inner.date_published,
        }
    }

    pub fn date_updated(&self) -> Option<OffsetDateTime> {
        match self {
            CveMetadata::Published(inner) => inner.date_updated,
            CveMetadata::Rejected(inner) => inner.date_updated,
        }
    }

    pub fn date_rejected(&self) -> Option<OffsetDateTime> {
        match self {
            CveMetadata::Published(_) => None,
            CveMetadata::Rejected(inner) => inner.date_rejected,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetadataPublished {
    pub cve_id: String,
    pub assigner_org_id: String,
    pub assigner_short_name: Option<String>,
    pub requester_user_id: Option<String>,
    pub serial: Option<u64>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub date_updated: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub date_reserved: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub date_published: Option<OffsetDateTime>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetadataRejected {
    pub cve_id: String,
    pub assigner_org_id: String,
    pub assigner_short_name: Option<String>,
    pub requester_user_id: Option<String>,
    pub serial: Option<u64>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub date_updated: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub date_reserved: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub date_published: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub date_rejected: Option<OffsetDateTime>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Containers {
    pub cna: CnaContainer,
    pub adp: Option<AdpContainer>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CnaContainer {
    pub title: Option<String>,
    pub descriptions: Vec<Description>,
    pub problem_types: Vec<ProblemType>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AdpContainer {
    pub descriptions: Vec<Description>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProblemType {
    pub descriptions: Vec<ProblemTypeDescription>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProblemTypeDescription {
    pub lang: String,
    pub description: String,
    pub cwe_id: Option<String>,
    pub r#type: Option<String>,
}

#[cfg(test)]
mod test {
    use crate::service::cve::cve_record::v5::CveRecord;
    use test_log::test;

    #[test(tokio::test)]
    async fn serde() -> Result<(), anyhow::Error> {
        let cve: CveRecord = serde_json::from_slice(include_bytes!(
            "../../../../../../etc/test-data/mitre/CVE-2024-28111.json"
        ))?;

        assert_eq!(cve.data_type, "CVE_RECORD");
        log::debug!("{:#?}", cve);

        Ok(())
    }
}
