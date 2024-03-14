use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetadataPublished {
    pub cve_id: String,
    pub assigner_org_id: String,
    pub assigner_short_name: Option<String>,
    pub requester_user_id: Option<String>,
    pub date_updated: Option<DateTime<Utc>>,
    pub serial: Option<u64>,
    pub date_reserved: Option<DateTime<Utc>>,
    pub date_published: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetadataRejected {
    pub cve_id: String,
    pub assigner_org_id: String,
    pub assigner_short_name: Option<String>,
    pub requester_user_id: Option<String>,
    pub date_updated: Option<DateTime<Utc>>,
    pub serial: Option<u64>,
    pub date_reserved: Option<DateTime<Utc>>,
    pub date_published: Option<DateTime<Utc>>,
    pub date_rejected: Option<DateTime<Utc>>,
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
    use crate::cve::cve_record::v5::CveRecord;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use test_log::test;

    #[test(tokio::test)]
    async fn serde() -> Result<(), anyhow::Error> {
        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../etc/test-data/mitre");

        let cve_json = test_data.join("CVE-2024-28111.json");

        let cve_file = File::open(cve_json)?;

        let cve: CveRecord = serde_json::from_reader(cve_file)?;

        println!("{:#?}", cve);

        Ok(())
    }
}
