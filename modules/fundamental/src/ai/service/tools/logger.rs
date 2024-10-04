use async_trait::async_trait;
use langchain_rust::tools::Tool;
use serde_json::Value;
use std::error::Error;

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
