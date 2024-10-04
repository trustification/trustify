use crate::ai::service::tools;
use crate::product::service::ProductService;
use anyhow::anyhow;
use async_trait::async_trait;
use langchain_rust::tools::Tool;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use trustify_common::db::query::Query;
use uuid::Uuid;

pub struct ProductInfo(pub ProductService);

#[async_trait]
impl Tool for ProductInfo {
    fn name(&self) -> String {
        String::from("product-info")
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
        tools::paginated_to_json(results, |item| Product {
            name: item.head.name.clone(),
            uuid: item.head.id,
            vendor: item.vendor.clone().map(|v| v.head.name),
            versions: item.versions.iter().map(|v| v.version.clone()).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::service::test::ingest_fixtures;
    use crate::ai::service::tools::tests::assert_tool_contains;
    use std::rc::Rc;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn product_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ingest_fixtures(ctx).await?;
        let tool = Rc::new(ProductInfo(ProductService::new(ctx.db.clone())));
        assert_tool_contains(
            tool.clone(),
            "Trusted Profile Analyzer",
            r#"
{
  "items": [
    {
      "name": "Trusted Profile Analyzer",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "vendor": "Red Hat",
      "versions": [
        "37.17.9"
      ]
    }
  ],
  "total": 1
}
"#,
        )
        .await
    }
}
