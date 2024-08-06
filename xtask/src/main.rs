#![allow(clippy::unwrap_used)]
#![recursion_limit = "256"]

use clap::{Parser, Subcommand};

mod dataset;
mod log;
mod openapi;

#[derive(Debug, Parser)]
pub struct Xtask {
    #[command(subcommand)]
    command: Command,
}

impl Xtask {
    pub async fn run(self) -> anyhow::Result<()> {
        match self.command {
            Command::ValidateOpenapi(command) => command.run(),
            Command::GenerateDump(command) => command.run().await,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate the generated OpenAPI spec
    ValidateOpenapi(openapi::Validate),
    /// Generate a sample data database dump
    GenerateDump(dataset::GenerateDump),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Xtask::parse().run().await
}
