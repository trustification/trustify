use crate::{
    ai::service::tools::{self, input_description},
    sbom::service::SbomService,
};
use async_trait::async_trait;
use itertools::Itertools;
use langchain_rust::tools::Tool;
use serde::Serialize;
use serde_json::Value;
use std::{error::Error, str::FromStr};
use time::OffsetDateTime;
use trustify_common::{db::query::Query, db::Database, id::Id};
use uuid::Uuid;

pub struct SbomInfo {
    pub db: Database,
    pub service: SbomService,
}

impl SbomInfo {
    pub fn new(db: Database) -> Self {
        let service = SbomService::new(db.clone());
        Self { db, service }
    }
}

#[async_trait]
impl Tool for SbomInfo {
    fn name(&self) -> String {
        String::from("sbom-info")
    }

    fn description(&self) -> String {
        String::from(
            r##"
This tool retrieves information about a Software Bill of Materials (SBOM). SBOMs are identified by SHA-256, SHA-384, SHA-512 hashes, or UUID URIs. Examples:

sha256:315f7c672f6e4948ffcc6d5a2b30f269c767d6d7d6f41d82ae716b5a46e5a68e
urn:uuid:2fd0d1b7-a908-4d63-9310-d57a7f77c6df

The tool provides a list of advisories/CVEs affecting the SBOM.
"##
                .trim(),
        )
    }

    fn parameters(&self) -> Value {
        input_description(
            r#"
An SBOM identifier or a product name.
A full SBOM name typically combines the product name and version (e.g., "product-version").
If a user specifies both, use the product name get a list of best matching SBOMs.
For example, input "quarkus" instead of "quarkus 3.2.11".
"#,
        )
    }

    async fn run(&self, input: Value) -> Result<String, Box<dyn Error>> {
        let service = &self.service;

        let input = input
            .as_str()
            .ok_or("Input should be a string")?
            .to_string();

        let mut sbom_details = match Id::from_str(input.as_str()) {
            Err(_) => None,
            Ok(id) => {
                log::info!("Fetching SBOM details by Id: {}", id);
                service.fetch_sbom_details(id, &self.db).await?
            }
        };

        if sbom_details.is_none() {
            sbom_details = match Uuid::from_str(input.as_str()) {
                Err(_) => None,
                Ok(id) => {
                    log::info!("Fetching SBOM details by UUID: {}", id);
                    service.fetch_sbom_details(Id::Uuid(id), &self.db).await?
                }
            };
        }

        // Fallback to search
        if sbom_details.is_none() {
            // try to search for possible matches
            let results = service
                .fetch_sboms(
                    Query {
                        q: input.clone(),
                        ..Default::default()
                    },
                    Default::default(),
                    (),
                    &self.db,
                )
                .await?;

            sbom_details = match results.items.len() {
                0 => None,
                1 => {
                    service
                        .fetch_sbom_details(Id::Uuid(results.items[0].head.id), &self.db)
                        .await?
                }
                _ => {
                    #[derive(Serialize)]
                    struct Item {
                        uuid: Uuid,
                        source_document_sha256: String,
                        name: String,
                        #[serde(with = "time::serde::rfc3339::option")]
                        published: Option<OffsetDateTime>,
                        link: String,
                    }

                    let json = tools::paginated_to_json(results, |item| Item {
                        uuid: item.head.id,
                        source_document_sha256: item
                            .source_document
                            .as_ref()
                            .map(|v| v.sha256.clone())
                            .unwrap_or_default(),
                        name: item.head.name.clone(),
                        published: item.head.published,
                        link: format!("http://localhost:3000/sboms/urn:uuid:{}", item.head.id),
                    })?;
                    return Ok(format!("There are multiple that match:\n\n{}", json));
                }
            };
        }

        let item = match sbom_details {
            Some(v) => v,
            None => return Ok(format!("SBOM '{input}' not found")),
        };

        #[derive(Serialize)]
        struct Item {
            uuid: Uuid,
            source_document_sha256: String,
            name: String,
            #[serde(with = "time::serde::rfc3339::option")]
            published: Option<OffsetDateTime>,
            authors: Vec<String>,
            labels: Vec<(String, String)>,
            advisories: Vec<Advisory>,
            link: String,
        }

        #[derive(Serialize)]
        struct Advisory {
            uuid: Uuid,
            identifier: String,
            issuer: Option<String>,
            link: String,
            vulnerabilities: Vec<Vulnerability>,
        }

        #[derive(Serialize)]
        struct Vulnerability {
            identifier: String,
            link: String,
        }

        let mut labels = item.summary.head.labels.iter().collect_vec();
        labels.sort_by(|a, b| a.0.cmp(b.0));

        tools::to_json(&Item {
            link: format!(
                "http://localhost:3000/sboms/urn:uuid:{}",
                item.summary.head.id
            ),
            uuid: item.summary.head.id,
            source_document_sha256: item
                .summary
                .source_document
                .as_ref()
                .map(|v| v.sha256.clone())
                .unwrap_or_default(),
            name: item.summary.head.name.clone(),
            published: item.summary.head.published,
            authors: item.summary.head.authors.clone(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            advisories: item
                .advisories
                .iter()
                .map(|advisory| Advisory {
                    uuid: advisory.head.uuid,
                    identifier: advisory.head.identifier.clone(),
                    issuer: advisory.head.issuer.clone().map(|v| v.head.name.clone()),
                    link: format!(
                        "http://localhost:3000/advisory/urn:uuid:{}",
                        advisory.head.uuid
                    ),
                    vulnerabilities: advisory
                        .status
                        .iter()
                        .map(|v| Vulnerability {
                            identifier: v.vulnerability.identifier.clone(),
                            link: format!(
                                "http://localhost:3000/vulnerability/{}",
                                v.vulnerability.identifier
                            ),
                        })
                        .collect(),
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::service::tools::tests::assert_tool_contains;
    use std::rc::Rc;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn sbom_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;
        ctx.ingest_document("quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json")
            .await?;

        let tool = Rc::new(SbomInfo::new(ctx.db.clone()));

        assert_tool_contains(
            tool.clone(),
            "quarkus",
            r#"
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "source_document_sha256": "sha256:5a370574a991aa42f7ecc5b7d88754b258f81c230a73bea247c0a6fcc6f608ab",
  "name": "quarkus-bom",
  "published": "2023-11-13T00:10:00Z",
  "authors": [
    "Organization: Red Hat Product Security (secalert@redhat.com)"
  ],
  "labels": [
    [
      "source",
      "TrustifyContext"
    ],
    [
      "type",
      "spdx"
    ]
  ],
  "advisories": [],
  "link": "http://localhost:3000/sboms/urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
"#,
        )
            .await
    }
}
