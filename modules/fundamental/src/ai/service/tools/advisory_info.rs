use crate::advisory::service::AdvisoryService;
use crate::ai::service::tools;
use anyhow::anyhow;
use async_trait::async_trait;
use langchain_rust::tools::Tool;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use time::OffsetDateTime;
use trustify_common::db::query::Query;
use trustify_common::id::Id;
use trustify_module_ingestor::common::Deprecation;
use uuid::Uuid;

pub struct AdvisoryInfo(pub AdvisoryService);

#[async_trait]
impl Tool for AdvisoryInfo {
    fn name(&self) -> String {
        String::from("advisory-info")
    }

    fn description(&self) -> String {
        String::from(
            r##"
This tool can be used to get information about an Advisory.
The input should be the name of the Advisory to search for.
When the input is a full name, the tool will provide information about the Advisory.
When the input is a partial name, the tool will provide a list of possible matches.
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

        // search for possible matches
        let results = service
            .fetch_advisories(
                Query {
                    q: input,
                    ..Default::default()
                },
                Default::default(),
                Deprecation::Ignore,
                (),
            )
            .await?;

        if results.items.is_empty() {
            return Err(anyhow!("I don't know").into());
        }

        // let the caller know what the possible matches are
        if results.items.len() > 1 {
            #[derive(Serialize)]
            struct Item {
                identifier: String,
                title: Option<String>,
            }

            let json = tools::paginated_to_json(results, |item| Item {
                identifier: item.head.identifier.clone(),
                title: item.head.title.clone(),
            })?;
            return Ok(format!("There are multiple that match:\n\n{}", json));
        }

        // let's show the details
        let item = match service
            .fetch_advisory(Id::Uuid(results.items[0].head.uuid), ())
            .await?
        {
            Some(v) => v,
            None => return Err(anyhow!("I don't know").into()),
        };

        #[derive(Serialize)]
        struct Item {
            uuid: Uuid,
            identifier: String,
            issuer: Option<String>,
            title: Option<String>,
            score: Option<f64>,
            severity: Option<String>,
            vulnerabilities: Vec<Vulnerability>,
        }
        #[derive(Serialize)]
        struct Vulnerability {
            identifier: String,
            title: Option<String>,
            description: Option<String>,
            #[serde(with = "time::serde::rfc3339::option")]
            released: Option<OffsetDateTime>,
        }

        let vulnerabilities = item
            .vulnerabilities
            .iter()
            .map(|v| Vulnerability {
                identifier: v.head.head.identifier.clone(),
                title: v.head.head.title.clone(),
                description: v.head.head.description.clone(),
                released: v.head.head.released,
            })
            .collect();

        tools::to_json(&Item {
            uuid: item.head.uuid,

            identifier: item.head.identifier.clone(),
            issuer: item.head.issuer.clone().map(|v| v.head.name),
            title: item.head.title.clone(),
            score: item.average_score,
            severity: item.average_severity.map(|v| v.to_string()),
            vulnerabilities,
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
    async fn advisory_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        crate::advisory::service::test::ingest_and_link_advisory(ctx).await?;
        crate::advisory::service::test::ingest_sample_advisory(ctx, "RHSA-2").await?;

        let tool = Rc::new(AdvisoryInfo(AdvisoryService::new(ctx.db.clone())));

        assert_tool_contains(
            tool.clone(),
            "RHSA-1",
            r#"
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "identifier": "RHSA-1",
  "issuer": null,
  "title": "RHSA-1",
  "score": 9.1,
  "severity": "critical",
  "vulnerabilities": [
    {
      "identifier": "CVE-123",
      "title": null,
      "description": null,
      "released": null
    }
  ]
}
"#,
        )
        .await
    }
}
