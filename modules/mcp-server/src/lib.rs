use anyhow::anyhow;
use rust_mcp_schema::{
    Implementation, InitializeResult, LATEST_PROTOCOL_VERSION, ServerCapabilities,
    ServerCapabilitiesTools,
};
use rust_mcp_sdk::error::MCPSdkError;
use rust_mcp_sdk::{
    MCPServer,
    error::SdkResult,
    mcp_server::{ServerRuntime, server_runtime},
};
use rust_mcp_transport::{StdioTransport, TransportOptions};
use std::process::ExitCode;

mod handler;
mod tools;

use handler::TrustifyServerHandler;
use trustify_common::config::Database;
use trustify_module_analysis::config::AnalysisConfig;
use trustify_module_storage::config::StorageConfig;

#[derive(clap::Args, Debug)]
pub struct Run {
    // flattened commands must go last
    //
    /// Analysis configuration
    #[command(flatten)]
    pub analysis: AnalysisConfig,

    /// Database configuration
    #[command(flatten)]
    pub database: Database,

    /// Location of the storage
    #[command(flatten)]
    pub storage: StorageConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        self.run_server()
            .await
            .map_err(|err| anyhow!("MCP server error: {err}"))?;
        Ok(ExitCode::SUCCESS)
    }

    async fn run_server(self) -> SdkResult<()> {
        let db = trustify_common::db::Database::new(&self.database)
            .await
            .map_err(|err| MCPSdkError::AnyError(Box::new(err)))?;

        // STEP 1: Define server details and capabilities
        let server_details = InitializeResult {
            // server name and version
            server_info: Implementation {
                name: "Trustify MCP Server".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            capabilities: ServerCapabilities {
                // indicates that server support mcp tools
                tools: Some(ServerCapabilitiesTools { list_changed: None }),
                ..Default::default() // Using default values for other fields
            },
            meta: None,
            instructions: Some("server instructions...".to_string()),
            protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
        };

        // STEP 2: create a std transport with default options
        let transport = StdioTransport::new(TransportOptions::default())?;

        // STEP 3: instantiate our custom handler for handling MCP messages
        let handler = TrustifyServerHandler { db };

        // STEP 4: create an MCP server
        let server: ServerRuntime =
            server_runtime::create_server(server_details, transport, handler);

        // STEP 5: Start the server
        server.start().await
    }
}
