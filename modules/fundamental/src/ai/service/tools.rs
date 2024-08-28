use std::error::Error;

use crate::product::service::ProductService;
use crate::vulnerability::service::VulnerabilityService;
use anyhow::anyhow;
use async_trait::async_trait;
use langchain_rust::tools::Tool;
use serde_json::Value;
use std::fmt::Write;
use trustify_common::db::query::Query;

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
            "##,
        )
    }

    async fn run(&self, input: Value) -> Result<String, Box<dyn Error>> {
        let service = &self.0;
        let query = Query {
            q: input
                .as_str()
                .ok_or("Input should be a string")?
                .to_string(),
            ..Default::default()
        };

        let results = service
            .fetch_products(query, Default::default(), ())
            .await?;

        if results.items.is_empty() {
            return Err(anyhow!("I don't know").into());
        }

        let mut result = "".to_string();
        for product in results.items {
            if let Some(vendor) = product.vendor {
                writeln!(
                    result,
                    r#"The product "{}" is made by vendor "{}"."#,
                    product.head.name, vendor.head.name
                )?;
            }
            if !product.versions.is_empty() {
                let versions = product
                    .versions
                    .iter()
                    .map(|v| v.version.clone())
                    .collect::<Vec<_>>();
                writeln!(
                    result,
                    r#"The product "{}" has the following versions: {:?}."#,
                    product.head.name, versions
                )?;
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
            The input should be the name of the Vulnerability to search for.
            "##,
        )
    }

    async fn run(&self, input: Value) -> Result<String, Box<dyn Error>> {
        let service = &self.0;

        let query = Query {
            q: input
                .as_str()
                .ok_or("Input should be a string")?
                .to_string(),
            ..Default::default()
        };

        let results = service
            .fetch_vulnerabilities(query, Default::default(), ())
            .await?;

        if results.items.is_empty() {
            return Err(anyhow!("I don't know").into());
        }

        let mut result = "".to_string();
        for item in results.items {
            writeln!(result, "ID: {}\n\n.", item.head.identifier)?;
            if let Some(v) = item.head.description {
                writeln!(result, "Description: {}\n\n.", v)?;
            }
            if let Some(v) = item.head.title {
                writeln!(result, "Title: {}\n\n.", v)?;
            }
        }
        Ok(result)
    }
}
