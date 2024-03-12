use std::process::ExitCode;

use clap::Subcommand;
use trustify_common::config::Database;

mod csaf;
mod progress;
mod sbom;

/// Importer
#[derive(Subcommand, Debug)]
pub enum ImporterCommand {
    Csaf(csaf::ImportCsafCommand),
    Sbom(sbom::ImportSbomCommand),
}

impl ImporterCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            ImporterCommand::Csaf(command) => command.run().await,
            ImporterCommand::Sbom(command) => command.run().await,
        }
    }
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct ImporterConfig {
    #[command(flatten)]
    pub database: Database,

    /// Source URL or path
    #[arg(short, long)]
    pub(crate) source: String,
}
