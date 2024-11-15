use crate::ai::service::tools;
use crate::purl::service::PurlService;
use crate::sbom::service::SbomService;
use async_trait::async_trait;
use langchain_rust::tools::Tool;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use trustify_common::db::query::Query;
use trustify_common::purl::Purl;
use trustify_module_ingestor::common::Deprecation;
use uuid::Uuid;

pub struct PackageInfo(pub (PurlService, SbomService));

#[async_trait]
impl Tool for PackageInfo {
    fn name(&self) -> String {
        String::from("package-info")
    }

    fn description(&self) -> String {
        String::from(
            r##"
This tool provides information about a Package, which has a name and version. Packages are identified by a URI or a UUID.

Examples of URIs:

* pkg:rpm/redhat/libsepol@3.5-1.el9?arch=ppc64le
* pkg:maven/org.apache.maven.wagon/wagon-provider-api@3.5.1?type=jar

Example of a UUID: 2fd0d1b7-a908-4d63-9310-d57a7f77c6df.

Example of package names:

* log4j
* openssl

Input: The package name, its Identifier URI, or UUID.
"##
                .trim(),
        )
    }

    async fn run(&self, input: Value) -> Result<String, Box<dyn Error>> {
        let (service, sbom_service) = &self.0;

        let input = input
            .as_str()
            .ok_or("Input should be a string")?
            .to_string();

        // Try lookup as a PURL
        let mut purl_details = match Purl::try_from(input.clone()) {
            Err(_) => None,
            Ok(purl) => service.purl_by_purl(&purl, Deprecation::Ignore, ()).await?,
        };

        // Try lookup as a UUID
        if purl_details.is_none() {
            purl_details = match Uuid::parse_str(input.as_str()) {
                Err(_) => None,
                Ok(uuid) => service.purl_by_uuid(&uuid, Deprecation::Ignore, ()).await?,
            };
        }

        // Fallback to search
        if purl_details.is_none() {
            // try to search for possible matches
            let results = service
                .purls(
                    Query {
                        q: input.clone(),
                        ..Default::default()
                    },
                    Default::default(),
                    (),
                )
                .await?;

            purl_details = match results.items.len() {
                0 => None,
                1 => {
                    service
                        .purl_by_uuid(&results.items[0].head.uuid, Deprecation::Ignore, ())
                        .await?
                }
                _ => {
                    #[derive(Serialize)]
                    struct Item {
                        identifier: Purl,
                        uuid: Uuid,
                        name: String,
                        version: Option<String>,
                    }

                    let json = tools::paginated_to_json(results, |item| Item {
                        identifier: item.head.purl.clone(),
                        uuid: item.head.uuid,
                        name: item.head.purl.name.clone(),
                        version: item.head.purl.version.clone(),
                    })?;
                    return Ok(format!("There are multiple that match:\n\n{}", json));
                }
            };
        }

        let item = match purl_details {
            Some(v) => v,
            None => return Ok(format!("Package '{input}' not found")),
        };

        let sboms = sbom_service
            .find_related_sboms(item.head.uuid, Default::default(), Default::default(), ())
            .await?;

        #[derive(Serialize)]
        struct Item {
            identifier: Purl,
            uuid: Uuid,
            name: String,
            version: Option<String>,
            advisories: Vec<Advisory>,
            licenses: Vec<String>,
            sboms: Vec<Sbom>,
        }

        #[derive(Serialize)]
        struct Sbom {
            uuid: Uuid,
            name: String,
        }

        #[derive(Serialize)]
        struct Advisory {
            uuid: Uuid,
            identifier: String,
            issuer: Option<String>,
            vulnerabilities: Vec<Vulnerability>,
        }

        #[derive(Serialize)]
        struct Vulnerability {
            identifier: String,
            title: Option<String>,
            status: String,
        }

        tools::to_json(&Item {
            identifier: item.head.purl.clone(),
            uuid: item.head.uuid,
            name: item.head.purl.name.clone(),
            version: item.head.purl.version.clone(),
            sboms: sboms
                .items
                .iter()
                .map(|sbom| Sbom {
                    uuid: sbom.head.id,
                    name: sbom.head.name.clone(),
                })
                .collect(),

            advisories: item
                .advisories
                .iter()
                .map(|advisory| Advisory {
                    uuid: advisory.head.uuid,
                    identifier: advisory.head.identifier.clone(),
                    issuer: advisory.head.issuer.clone().map(|v| v.head.name.clone()),
                    vulnerabilities: advisory
                        .status
                        .iter()
                        .map(|status| Vulnerability {
                            identifier: status.vulnerability.identifier.clone(),
                            title: status.vulnerability.title.clone(),
                            status: status.status.clone(),
                        })
                        .collect(),
                })
                .collect(),

            licenses: item
                .licenses
                .iter()
                .flat_map(|v| v.licenses.iter())
                .cloned()
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
    async fn package_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;
        ctx.ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
            .await?;

        let tool = Rc::new(PackageInfo((
            PurlService::new(ctx.db.clone()),
            SbomService::new(ctx.db.clone()),
        )));

        assert_tool_contains(
            tool.clone(),
            "pkg:rpm/redhat/libsepol@3.5-1.el9?arch=s390x",
            r#"
{
  "identifier": "pkg:rpm/redhat/libsepol@3.5-1.el9?arch=ppc64le",
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "libsepol",
  "version": "3.5-1.el9",
  "advisories": [],
  "licenses": [
    "LGPLV2+"
  ],
  "sboms": [
    {
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "ubi9-container"
    }
  ]
}
"#,
        )
        .await?;

        assert_tool_contains(
            tool.clone(),
            "1ca731c3-9596-534c-98eb-8dcc6ff7fef9",
            r#"
{
  "identifier": "pkg:rpm/redhat/libsepol@3.5-1.el9?arch=ppc64le",
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "libsepol",
  "version": "3.5-1.el9",
  "advisories": [],
  "licenses": [
    "LGPLV2+"
  ],
  "sboms": [
    {
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "ubi9-container"
    }
  ]
}
"#,
        )
        .await?;

        assert_tool_contains(
            tool.clone(),
            "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
            r#"
{
  "identifier": "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "commons-logging-jboss-logging",
  "version": "1.0.0.Final-redhat-1",
  "advisories": [],
  "licenses": [
    "APACHE-2.0"
  ],
  "sboms": [
    {
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-bom"
    }
  ]
}
"#).await?;

        assert_tool_contains(
            tool.clone(),
            "commons-logging-jboss-logging",
            r#"
{
  "identifier": "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "commons-logging-jboss-logging",
  "version": "1.0.0.Final-redhat-1",
  "advisories": [],
  "licenses": [
    "APACHE-2.0"
  ],
  "sboms": [
    {
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-bom"
    }
  ]
}
"#).await?;

        assert_tool_contains(
            tool.clone(),
            "quarkus-resteasy-reactive-json",
            r#"
There are multiple that match:

{
  "items": [
    {
      "identifier": "pkg:maven/io.quarkus/quarkus-resteasy-reactive-jsonb-common@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-resteasy-reactive-jsonb-common",
      "version": "2.13.8.Final-redhat-00004"
    },
    {
      "identifier": "pkg:maven/io.quarkus/quarkus-resteasy-reactive-jsonb@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-resteasy-reactive-jsonb",
      "version": "2.13.8.Final-redhat-00004"
    },
    {
      "identifier": "pkg:maven/io.quarkus/quarkus-resteasy-reactive-jsonb-common-deployment@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-resteasy-reactive-jsonb-common-deployment",
      "version": "2.13.8.Final-redhat-00004"
    },
    {
      "identifier": "pkg:maven/io.quarkus/quarkus-resteasy-reactive-jsonb-deployment@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-resteasy-reactive-jsonb-deployment",
      "version": "2.13.8.Final-redhat-00004"
    }
  ],
  "total": 4
}
"#).await
    }
}
