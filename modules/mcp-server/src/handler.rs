use crate::tools::TrustifyTools;
use async_trait::async_trait;
use rust_mcp_schema::{
    CallToolRequest, CallToolResult, ListToolsRequest, ListToolsResult, RpcError,
    schema_utils::CallToolError,
};
use rust_mcp_sdk::{MCPServer, mcp_server::ServerHandler};
use trustify_common::db::Database;

// Custom Handler to handle MCP Messages
pub struct TrustifyServerHandler {
    pub db: Database,
}

// To check out a list of all the methods in the trait that you can override, take a look at
// https://github.com/rust-mcp-stack/rust-mcp-sdk/blob/main/crates/rust-mcp-sdk/src/mcp_handlers/mcp_server_handler.rs

#[async_trait]
impl ServerHandler for TrustifyServerHandler {
    // Handle ListToolsRequest, return list of available tools as ListToolsResult
    async fn handle_list_tools_request(
        &self,
        _request: ListToolsRequest,
        _runtime: &dyn MCPServer,
    ) -> Result<ListToolsResult, RpcError> {
        Ok(ListToolsResult {
            meta: None,
            next_cursor: None,
            tools: TrustifyTools::get_tools(),
        })
    }

    /// Handles incoming CallToolRequest and processes it using the appropriate tool.
    async fn handle_call_tool_request(
        &self,
        request: CallToolRequest,
        _runtime: &dyn MCPServer,
    ) -> Result<CallToolResult, CallToolError> {
        // Attempt to convert request parameters into GreetingTools enum
        let tool_params: TrustifyTools =
            TrustifyTools::try_from(request.params).map_err(CallToolError::new)?;

        // Match the tool variant and execute its corresponding logic
        match tool_params {
            TrustifyTools::GetAdvisoryInformation(tool) => tool.call_tool(&self.db).await,
            TrustifyTools::GetVulnerabilityInformation(tool) => tool.call_tool(&self.db).await,
        }
    }
}
