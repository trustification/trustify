use crate::ai::service::tools;
use crate::sbom::service::SbomService;
use anyhow::anyhow;
use async_trait::async_trait;
use itertools::Itertools;
use langchain_rust::tools::Tool;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use std::str::FromStr;
use time::OffsetDateTime;
use trustify_common::db::query::Query;
use trustify_common::id::Id;
use uuid::Uuid;

pub struct SbomInfo(pub SbomService);

#[async_trait]
impl Tool for SbomInfo {
    fn name(&self) -> String {
        String::from("sbom-info")
    }

    fn description(&self) -> String {
        String::from(
            r##"
This tool can be used to get information about an SBOM.
The input should be the SBOM Identifier.
"##
            .trim(),
        )
    }

    async fn run(&self, input: Value) -> Result<String, Box<dyn Error>> {
        let service = &self.0;

        let input = input
            .as_str()
            .ok_or("Input should be a string")?
            .to_string();

        // Try lookup as a UUID
        let mut sbom_details = match Id::from_str(input.as_str()) {
            Err(_) => None,
            Ok(id) => service.fetch_sbom_details(id, ()).await?,
        };

        // Fallback to search
        if sbom_details.is_none() {
            // try to search for possible matches
            let results = service
                .fetch_sboms(
                    Query {
                        q: input,
                        ..Default::default()
                    },
                    Default::default(),
                    (),
                    (),
                )
                .await?;

            sbom_details = match results.items.len() {
                0 => None,
                1 => {
                    service
                        .fetch_sbom_details(Id::Uuid(results.items[0].head.id), ())
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
                    })?;
                    return Ok(format!("There are multiple that match:\n\n{}", json));
                }
            };
        }

        let item = match sbom_details {
            Some(v) => v,
            None => return Err(anyhow!("I don't know").into()),
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
        }

        #[derive(Serialize)]
        struct Advisory {
            uuid: Uuid,
            identifier: String,
            issuer: Option<String>,
        }

        let mut labels = item.summary.head.labels.iter().collect_vec();
        labels.sort_by(|a, b| a.0.cmp(b.0));

        tools::to_json(&Item {
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

        let tool = Rc::new(SbomInfo(SbomService::new(ctx.db.clone())));

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
  "advisories": []
}
"#,
        )
            .await
    }
}
