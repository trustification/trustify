use crate::{
    advisory::service::AdvisoryService, product::service::ProductService,
    purl::service::PurlService, sbom::service::SbomService,
    vulnerability::service::VulnerabilityService,
};
use anyhow::anyhow;
use async_trait::async_trait;
use itertools::Itertools;
use langchain_rust::tools::Tool;
use serde::Serialize;
use serde_json::Value;
use std::{error::Error, fmt::Write, str::FromStr};
use time::OffsetDateTime;
use trustify_common::model::PaginatedResults;
use trustify_common::{db::query::Query, id::Id, purl::Purl};
use trustify_module_ingestor::common::Deprecation;
use uuid::Uuid;

fn to_json<T>(value: &T) -> Result<String, Box<dyn Error>>
where
    T: Serialize,
{
    #[cfg(test)]
    {
        serde_json::to_string_pretty(&value).map_err(|e| e.into())
    }
    #[cfg(not(test))]
    {
        serde_json::to_string(&value).map_err(|e| e.into())
    }
}

fn paginated_to_json<A, T>(p: PaginatedResults<A>, f: fn(&A) -> T) -> Result<String, Box<dyn Error>>
where
    T: Serialize,
{
    to_json(&PaginatedResults {
        items: p.items.iter().map(f).collect(),
        total: p.total,
    })
}

pub struct ToolLogger<T: Tool>(pub T);

#[async_trait]
impl<T: Tool> Tool for ToolLogger<T> {
    fn name(&self) -> String {
        self.0.name()
    }

    fn description(&self) -> String {
        self.0.description()
    }

    fn parameters(&self) -> Value {
        self.0.parameters()
    }

    async fn call(&self, input: &str) -> Result<String, Box<dyn Error>> {
        log::info!("  tool call: {}, input: {}", self.name(), input);
        let result = self.0.call(input).await;
        match &result {
            Ok(result) => {
                log::info!("     ok: {}", result);
            }
            Err(err) => {
                log::info!("     err: {}", err);
            }
        }
        result
    }

    async fn run(&self, input: Value) -> Result<String, Box<dyn Error>> {
        self.0.run(input).await
    }

    async fn parse_input(&self, input: &str) -> Value {
        self.0.parse_input(input).await
    }
}

pub struct ProductInfo(pub ProductService);

#[async_trait]
impl Tool for ProductInfo {
    fn name(&self) -> String {
        String::from("ProductInfo")
    }

    fn description(&self) -> String {
        String::from(
            r##"
This tool can be used to get information about a product.
The input should be the name of the product to search for.
When the input is a full name, the tool will provide information about the product.
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

        let results = service
            .fetch_products(
                Query {
                    q: input,
                    ..Default::default()
                },
                Default::default(),
                (),
            )
            .await?;

        if results.items.is_empty() {
            return Err(anyhow!("I don't know").into());
        }

        #[derive(Serialize)]
        struct Product {
            name: String,
            uuid: Uuid,
            vendor: Option<String>,
            versions: Vec<String>,
        }
        paginated_to_json(results, |item| Product {
            name: item.head.name.clone(),
            uuid: item.head.id,
            vendor: item.vendor.clone().map(|v| v.head.name),
            versions: item.versions.iter().map(|v| v.version.clone()).collect(),
        })
    }
}

pub struct CVEInfo(pub VulnerabilityService);

#[async_trait]
impl Tool for CVEInfo {
    fn name(&self) -> String {
        String::from("CVEInfo")
    }

    fn description(&self) -> String {
        String::from(
            r##"
This tool can be used to get information about a Vulnerability.
The input should be the partial name of the Vulnerability to search for.
When the input is a full CVE ID, the tool will provide information about the vulnerability.
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

        let item = match service
            .fetch_vulnerability(input.as_str(), Deprecation::Ignore, ())
            .await?
        {
            Some(v) => v,
            None => {
                // search for possible matches
                let results = service
                    .fetch_vulnerabilities(
                        Query {
                            q: input.clone(),
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
                        name: Option<String>,
                    }

                    let json = paginated_to_json(results, |item| Item {
                        identifier: item.head.identifier.clone(),
                        name: item.head.title.clone(),
                    })?;
                    return Ok(format!("There are multiple that match:\n\n{}", json));
                }

                // let's show the details for the one that matched.
                if let Some(v) = service
                    .fetch_vulnerability(
                        results.items[0].head.identifier.as_str(),
                        Deprecation::Ignore,
                        (),
                    )
                    .await?
                {
                    v
                } else {
                    return Err(anyhow!("I don't know").into());
                }
            }
        };

        #[derive(Serialize)]
        struct Item {
            title: Option<String>,
            description: Option<String>,
            severity: Option<f64>,
            score: Option<f64>,
            #[serde(with = "time::serde::rfc3339::option")]
            released: Option<OffsetDateTime>,
            affected_packages: Vec<Package>,
        }
        #[derive(Serialize)]
        struct Package {
            name: Purl,
            version: String,
        }

        let affected_packages = item
            .advisories
            .iter()
            .flat_map(|v| {
                v.purls
                    .get("affected")
                    .into_iter()
                    .flatten()
                    .map(|v| Package {
                        name: v.base_purl.purl.clone(),
                        version: v.version.clone(),
                    })
            })
            .collect();
        let json = to_json(&Item {
            title: item.head.title.clone(),
            description: item.head.description.clone(),
            severity: item.average_score,
            score: item.average_score,
            released: item.head.released,
            affected_packages,
        })?;

        let mut result = "".to_string();
        if item.head.identifier != input {
            writeln!(result, "There is one match, but it had a different identifier.  Inform the user that that you are providing information on: {}\n", item.head.identifier)?;
        }
        writeln!(result, "{}", json)?;
        Ok(result)
    }
}

pub struct AdvisoryInfo(pub AdvisoryService);

#[async_trait]
impl Tool for AdvisoryInfo {
    fn name(&self) -> String {
        String::from("AdvisoryInfo")
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

            let json = paginated_to_json(results, |item| Item {
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

        to_json(&Item {
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

pub struct PackageInfo(pub PurlService);

#[async_trait]
impl Tool for PackageInfo {
    fn name(&self) -> String {
        String::from("PackageInfo")
    }

    fn description(&self) -> String {
        String::from(
            r##"
This tool can be used to get information about a Package.
The input should be the name of the package, it's Identifier uri or internal UUID.
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
                        q: input,
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

                    let json = paginated_to_json(results, |item| Item {
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
            None => return Err(anyhow!("I don't know").into()),
        };

        #[derive(Serialize)]
        struct Item {
            identifier: Purl,
            uuid: Uuid,
            name: String,
            version: Option<String>,
            advisories: Vec<Advisory>,
            licenses: Vec<String>,
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

        to_json(&Item {
            identifier: item.head.purl.clone(),
            uuid: item.head.uuid,
            name: item.head.purl.name.clone(),
            version: item.head.purl.version.clone(),

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

pub struct SbomInfo(pub SbomService);

#[async_trait]
impl Tool for SbomInfo {
    fn name(&self) -> String {
        String::from("SbomInfo")
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

                    let json = paginated_to_json(results, |item| Item {
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

        to_json(&Item {
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
