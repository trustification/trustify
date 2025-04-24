use rust_mcp_macros::{JsonSchema, mcp_tool};
use rust_mcp_schema::{
    CallToolResult, EmbeddedResourceAnnotations, Role, TextResourceContents,
    schema_utils::CallToolError,
};
use rust_mcp_sdk::tool_box;
use trustify_common::{db::Database, db::query::Query, model::Paginated};
use trustify_module_fundamental::advisory::service::AdvisoryService;
use trustify_module_fundamental::vulnerability::service::VulnerabilityService;
use trustify_module_ingestor::common::Deprecation;

#[mcp_tool(
    name = "get_advisory_information",
    description = "Get information about an advisory"
)]
#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct GetAdvisoryInformation {
    /// The name of the advisory.
    name: String,
}

impl GetAdvisoryInformation {
    pub async fn call_tool(&self, db: &Database) -> Result<CallToolResult, CallToolError> {
        let search = Query::q(&format!(
            "identifier={}",
            self.name.replace('\\', "\\\\").replace('&', "\\&")
        ));

        let service = AdvisoryService::new(db.clone());
        let result = service
            .fetch_advisories(
                search,
                Paginated {
                    limit: 10,
                    offset: 0,
                },
                Deprecation::Ignore,
                db,
            )
            .await
            .map_err(CallToolError::new)?;

        let json = serde_json::to_string(&result).map_err(CallToolError::new)?;

        Ok(CallToolResult::embedded_resource(
            TextResourceContents {
                text: json,
                uri: "".to_string(),
                mime_type: Some("application/json".to_string()),
            }
            .into(),
            Some(EmbeddedResourceAnnotations {
                audience: vec![Role::Assistant, Role::User],
                priority: None,
            }),
        ))
    }
}

#[mcp_tool(
    name = "get_vulnerability_information",
    description = "Get information about a vulnerability"
)]
#[derive(Debug, serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct GetVulnerabilityInformation {
    /// The name of the vulnerability.
    name: String,
}

impl GetVulnerabilityInformation {
    pub async fn call_tool(&self, db: &Database) -> Result<CallToolResult, CallToolError> {
        let service = VulnerabilityService::new();
        let result = service
            .fetch_vulnerability(&self.name, Deprecation::Ignore, db)
            .await
            .map_err(CallToolError::new)?;

        let json = serde_json::to_string(&result).map_err(CallToolError::new)?;

        Ok(CallToolResult::embedded_resource(
            TextResourceContents {
                text: json,
                uri: "".to_string(),
                mime_type: Some("application/json".to_string()),
            }
            .into(),
            Some(EmbeddedResourceAnnotations {
                audience: vec![Role::Assistant, Role::User],
                priority: None,
            }),
        ))
    }
}

// Generates an enum names GreetingTools, with SayHelloTool and SayGoodbyeTool variants
tool_box!(
    TrustifyTools,
    [GetAdvisoryInformation, GetVulnerabilityInformation]
);
