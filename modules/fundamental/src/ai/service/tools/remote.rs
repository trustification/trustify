use crate::ai::model::AiTool;
use crate::ai::service::tools::logger::ToolLogger;
use async_trait::async_trait;
use langchain_rust::tools::Tool;
use serde_json::Value;
use std::error::Error;
use std::sync::Arc;

pub struct RemoteTool {
    url: String,
    name: String,
    description: String,
    parameters: Value,
}

#[async_trait]
impl Tool for RemoteTool {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn description(&self) -> String {
        self.description.clone()
    }

    fn parameters(&self) -> Value {
        self.parameters.clone()
    }

    async fn call(&self, input: &str) -> Result<String, Box<dyn Error>> {
        let client = reqwest::Client::new();

        let input = input.to_string();
        let res = client
            .post(self.url.as_str())
            .header("Content-Type", "application/json")
            .body(input)
            .send()
            .await?;
        let res = res.error_for_status()?;

        // res.error_for_status().map_err(|err| Err(anyhow::anyhow!(err).into()))?;

        Ok(res.text().await?)
    }

    async fn run(&self, _input: Value) -> Result<String, Box<dyn Error>> {
        panic!("use the call function")
    }
}

pub struct RemoteToolsProvider {
    id: String,
    url: String,
}

impl RemoteToolsProvider {
    pub fn new(id: String, url: String) -> Self {
        Self { id, url }
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub async fn tools(&self) -> Result<Vec<Arc<dyn Tool>>, Box<dyn Error>> {
        let res = reqwest::get(self.url.as_str()).await?;
        let res = res.error_for_status()?;

        let tools = res.json::<Vec<AiTool>>().await?;

        let mut result: Vec<Arc<dyn Tool>> = vec![];
        for tool in tools {
            result.push(Arc::new(ToolLogger(RemoteTool {
                url: format!("{}/{}", self.url, tool.name),
                name: format!("{}_{}", self.id, tool.name),
                description: tool.description,
                parameters: tool.parameters,
            })));
        }
        Ok(result)
    }
}
