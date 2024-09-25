use crate::{
    advisory::service::AdvisoryService, product::service::ProductService,
    purl::service::PurlService, sbom::service::SbomService,
    vulnerability::service::VulnerabilityService,
};
use anyhow::anyhow;
use async_trait::async_trait;
use itertools::Itertools;
use langchain_rust::tools::Tool;
use serde_json::Value;
use std::{error::Error, fmt::Write, str::FromStr};
use trustify_common::{db::query::Query, id::Id, purl::Purl};
use trustify_module_ingestor::common::Deprecation;
use uuid::Uuid;

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

        let mut result = match results.items.len() {
            0 => return Err(anyhow!("I don't know").into()),
            1 => "Found one matching product:\n",
            _ => "There are multiple products that match:\n",
        }
        .to_string();

        for product in results.items {
            writeln!(result, "  * Name: {}", product.head.name)?;
            writeln!(result, "    UUID: {}", product.head.id)?;
            if let Some(v) = product.vendor {
                writeln!(result, "    Vendor: {}", v.head.name)?;
            }
            if !product.versions.is_empty() {
                writeln!(result, "    Versions:")?;
                for version in product.versions {
                    writeln!(result, "      * {}", version.version)?;
                }
            }
        }
        Ok(result)
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

        // is it a CVE ID?
        let mut result = "".to_string();

        let vuln = match service
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

                match results.items.len() {
                    0 => return Err(anyhow!("I don't know").into()),
                    1 => writeln!(result, "There is one advisory that matches:")?,
                    _ => writeln!(result, "There are multiple advisories that match:")?,
                }

                // let the caller know what the possible matches are
                if results.items.len() > 1 {
                    for item in results.items {
                        writeln!(result, "* Identifier: {}", item.head.identifier)?;
                        if let Some(v) = item.head.title {
                            writeln!(result, "  Title: {}", v)?;
                        }
                    }
                    return Ok(result);
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

        writeln!(result, "But it had a different identifier.  Please inform the user that that you are providing information on vulnerability: {}\n", vuln.head.identifier)?;

        if vuln.head.identifier != input {
            writeln!(result, "Identifier: {}", vuln.head.identifier)?;
        }

        writeln!(result, "Identifier: {}", vuln.head.identifier)?;
        if let Some(v) = vuln.head.title {
            writeln!(result, "Title: {}", v)?;
        }
        if let Some(v) = vuln.head.description {
            writeln!(result, "Description: {}", v)?;
        }
        if let Some(v) = vuln.average_score {
            writeln!(result, "Severity: {}", v)?;
            writeln!(result, "Score: {}", v)?;
        }
        if let Some(v) = vuln.head.released {
            writeln!(result, "Released: {}", v)?;
        }

        writeln!(result, "Affected Packages:")?;
        vuln.advisories.iter().for_each(|advisory| {
            if let Some(v) = advisory.purls.get("affected") {
                v.iter().for_each(|advisory| {
                    _ = writeln!(result, "  * Name: {}", advisory.base_purl.purl);
                    _ = writeln!(result, "    Version: {}", advisory.version);
                });
            }
        });
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

        let mut result = match results.items.len() {
            0 => return Err(anyhow!("I don't know").into()),
            1 => "There is one advisory that matches:\n",
            _ => "There are multiple advisories that match:\n",
        }
        .to_string();

        // let the caller know what the possible matches are
        if results.items.len() > 1 {
            for item in results.items {
                writeln!(result, "* Identifier: {}", item.head.identifier)?;
                if let Some(v) = item.head.title {
                    writeln!(result, "  Title: {}", v)?;
                }
            }
            return Ok(result);
        }

        // let's show the details
        let item = match service
            .fetch_advisory(Id::Uuid(results.items[0].head.uuid), ())
            .await?
        {
            Some(v) => v,
            None => return Err(anyhow!("I don't know").into()),
        };

        let mut result = "".to_string();
        writeln!(result, "UUID: {}", item.head.uuid)?;
        writeln!(result, "Identifier: {}", item.head.identifier)?;
        if let Some(v) = item.head.issuer {
            writeln!(result, "Issuer: {}", v.head.name)?;
        }
        if let Some(v) = item.head.title {
            writeln!(result, "Title: {}", v)?;
        }
        if let Some(v) = item.average_score {
            writeln!(result, "Score: {}", v)?;
        }
        if let Some(v) = item.average_severity {
            writeln!(result, "Severity: {}", v)?;
        }

        writeln!(result, "Vulnerabilities:")?;
        item.vulnerabilities.iter().for_each(|v| {
            let vuln = &v.head;
            _ = writeln!(result, " * Identifier: {}", vuln.head.identifier);
            if let Some(v) = &vuln.head.title {
                _ = writeln!(result, "   Title: {}", v);
            }
            if let Some(v) = &vuln.head.description {
                _ = writeln!(result, "   Description: {}", v);
            }
            if let Some(v) = &vuln.head.released {
                _ = writeln!(result, "   Released: {}", v);
            }
        });
        Ok(result)
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
                    let mut result = "There are multiple packages that match:\n".to_string();
                    for item in results.items {
                        writeln!(result, " * Identifier: {}", item.head.purl)?;
                        writeln!(result, "   UUID: {}", item.head.uuid)?;
                        writeln!(result, "   Name: {}", item.head.purl.name)?;
                        if let Some(v) = &item.head.purl.version {
                            writeln!(result, "   Version: {}", v)?;
                        }
                    }
                    return Ok(result);
                }
            };
        }

        let item = match purl_details {
            Some(v) => v,
            None => return Err(anyhow!("I don't know").into()),
        };

        let mut result = "There is one package that matches:\n".to_string();
        writeln!(result, "Identifier: {}", item.head.purl)?;
        writeln!(result, "UUID: {}", item.head.uuid)?;
        writeln!(result, "Name: {}", item.head.purl.name)?;
        if let Some(v) = &item.head.purl.version {
            _ = writeln!(result, "Version: {}", v);
        }

        if !item.advisories.is_empty() {
            writeln!(result, "Advisories:")?;
            item.advisories.iter().for_each(|advisory| {
                _ = writeln!(result, " * UUID: {}", advisory.head.uuid);
                _ = writeln!(result, "   Identifier: {}", advisory.head.identifier);
                if let Some(v) = &advisory.head.issuer {
                    _ = writeln!(result, "   Issuer: {}", v.head.name);
                }
                if !advisory.status.is_empty() {
                    _ = writeln!(result, "   Vulnerabilities:");
                    advisory.status.iter().for_each(|status| {
                        _ = writeln!(
                            result,
                            "    * Identifier: {}",
                            status.vulnerability.identifier
                        );
                        if let Some(v) = &status.vulnerability.title {
                            _ = writeln!(result, "      Title: {}", v);
                        }
                        _ = writeln!(result, "      Status: {}", status.status);
                        // if let Some(v) = &status.context {
                        //     _ = writeln!(result, "      StatusContext: {}", v);
                        // }
                    });
                }
            });
        }
        if !item.licenses.is_empty() {
            writeln!(result, "Licenses:")?;
            item.licenses.iter().for_each(|license| {
                license.licenses.iter().for_each(|license| {
                    _ = writeln!(result, " * Name: {}", license);
                })
            });
        }
        Ok(result)
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
                    let mut result = "There are multiple SBOMs that match:\n".to_string();
                    for item in results.items {
                        writeln!(result, " * UUID: {}", item.head.id)?;
                        if let Some(v) = &item.source_document {
                            writeln!(result, "   SHA256: {}", v.sha256)?;
                        }
                        writeln!(result, "   Name: {}", item.head.name)?;
                        if let Some(v) = &item.head.published {
                            writeln!(result, "   Published: {}", v)?;
                        }
                    }
                    return Ok(result);
                }
            };
        }

        let item = match sbom_details {
            Some(v) => v,
            None => return Err(anyhow!("I don't know").into()),
        };

        let mut result = "There is one SBOM that matches:\n".to_string();

        writeln!(result, " * UUID: {}", item.summary.head.id)?;
        if let Some(v) = &item.summary.source_document {
            writeln!(result, "   SHA256: {}", v.sha256)?;
        }
        writeln!(result, "   Name: {}", item.summary.head.name)?;
        if let Some(v) = &item.summary.head.published {
            writeln!(result, "   Published: {}", v)?;
        }
        if !item.summary.head.authors.is_empty() {
            writeln!(result, "   Authors:")?;
            item.summary.head.authors.iter().for_each(|author| {
                _ = writeln!(result, "    * {}", author);
            });
        }
        if !item.summary.head.labels.is_empty() {
            writeln!(result, "   Labels:")?;
            let mut labels = item.summary.head.labels.iter().collect_vec();
            labels.sort_by(|a, b| a.0.cmp(b.0));
            labels.iter().for_each(|(key, value)| {
                _ = writeln!(result, "    * {}: {}", key, value);
            });
        }

        if !item.advisories.is_empty() {
            writeln!(result, "   Advisories:")?;
            item.advisories.iter().for_each(|advisory| {
                _ = writeln!(result, "    * UUID: {}", advisory.head.uuid);
                _ = writeln!(result, "      Identifier: {}", advisory.head.identifier);
                if let Some(v) = &advisory.head.issuer {
                    _ = writeln!(result, "      Issuer: {}", v.head.name);
                }
            });
        }
        Ok(result)
    }
}
