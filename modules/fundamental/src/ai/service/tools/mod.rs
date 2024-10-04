use crate::advisory::service::AdvisoryService;
use crate::ai::service::tools::advisory_info::AdvisoryInfo;
use crate::ai::service::tools::cve_info::CVEInfo;
use crate::ai::service::tools::logger::ToolLogger;
use crate::ai::service::tools::package_info::PackageInfo;
use crate::ai::service::tools::product_info::ProductInfo;
use crate::ai::service::tools::sbom_info::SbomInfo;
use crate::product::service::ProductService;
use crate::purl::service::PurlService;
use crate::sbom::service::SbomService;
use crate::vulnerability::service::VulnerabilityService;
use langchain_rust::tools::Tool;
use serde::Serialize;
use std::error::Error;
use std::sync::Arc;
use trustify_common::db::Database;
use trustify_common::model::PaginatedResults;

pub mod advisory_info;
pub mod cve_info;
pub mod logger;
pub mod package_info;
pub mod product_info;
pub mod sbom_info;

pub fn new(db: Database) -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(ToolLogger(ProductInfo(ProductService::new(db.clone())))),
        Arc::new(ToolLogger(CVEInfo(VulnerabilityService::new(db.clone())))),
        Arc::new(ToolLogger(AdvisoryInfo(AdvisoryService::new(db.clone())))),
        Arc::new(ToolLogger(PackageInfo(PurlService::new(db.clone())))),
        Arc::new(ToolLogger(SbomInfo(SbomService::new(db.clone())))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::service::test::sanitize_uuid;
    use langchain_rust::tools::Tool;
    use serde_json::Value;
    use std::rc::Rc;

    pub fn cleanup_tool_result(s: Result<String, Box<dyn Error>>) -> String {
        sanitize_uuid(s.unwrap().trim().to_string())
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
