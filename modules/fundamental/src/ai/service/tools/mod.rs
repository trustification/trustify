use crate::ai::service::tools::{
    advisory_info::AdvisoryInfo, cve_info::CVEInfo, logger::ToolLogger, package_info::PackageInfo,
    sbom_info::SbomInfo,
};
use langchain_rust::tools::Tool;
use serde::Serialize;
use serde_json::{json, Value};
use std::{error::Error, sync::Arc};
use trustify_common::{db::Database, model::PaginatedResults};

pub mod advisory_info;
pub mod cve_info;
pub mod logger;
pub mod package_info;
pub mod product_info;
pub mod remote;
pub mod sbom_info;

pub fn new(db: Database) -> Vec<Arc<dyn Tool>> {
    vec![
        // Arc::new(ToolLogger(ProductInfo(ProductService::new(db.clone())))),
        Arc::new(ToolLogger(CVEInfo::new(db.clone()))),
        Arc::new(ToolLogger(AdvisoryInfo::new(db.clone()))),
        Arc::new(ToolLogger(PackageInfo::new(db.clone()))),
        Arc::new(ToolLogger(SbomInfo::new(db.clone()))),
    ]
}

pub fn to_json<T>(value: &T) -> Result<String, Box<dyn Error>>
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

pub fn paginated_to_json<A, T>(
    p: PaginatedResults<A>,
    f: fn(&A) -> T,
) -> Result<String, Box<dyn Error>>
where
    T: Serialize,
{
    to_json(&PaginatedResults {
        items: p.items.iter().map(f).collect(),
        total: p.total,
    })
}

fn input_description(description: &str) -> Value {
    json!({
        "type": "object",
            "properties": {
            "input": {
                "type": "string",
                "description": description,
            }
        },
        "required": ["input"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::service::test::{sanitize_uuid_field, sanitize_uuid_urn};
    use langchain_rust::tools::Tool;
    use serde_json::Value;
    use std::rc::Rc;

    pub fn cleanup_tool_result(s: Result<String, Box<dyn Error>>) -> String {
        sanitize_uuid_urn(sanitize_uuid_field(s.unwrap().trim().to_string()))
    }

    pub async fn assert_tool_contains(
        tool: Rc<dyn Tool>,
        input: &str,
        expected: &str,
    ) -> Result<(), anyhow::Error> {
        let actual = cleanup_tool_result(tool.run(Value::String(input.to_string())).await);
        assert!(
            actual.contains(expected.trim()),
            "actual:\n{}\nexpected:\n{}\n",
            actual,
            expected
        );
        Ok(())
    }
}
