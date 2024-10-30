use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Error, Result};
use trustify_server::openapi::create_openapi;

#[derive(clap::Args, Debug)]
pub struct Run {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Export(Export),
}

impl Run {
    pub async fn run(self) -> Result<ExitCode> {
        use Command::*;
        match self.command {
            Export(export) => export.run().await,
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct Export {
    /// The file the openapi spec should be exported to
    #[arg(long, env)]
    pub file: PathBuf,
}

impl Export {
    pub async fn run(self) -> Result<ExitCode> {
        let doc = match self.file.file_name() {
            Some(name) => {
                let name = name.to_string_lossy();
                if name.is_empty() {
                    return Err(anyhow!("Invalid file name"));
                }

                let api = create_openapi().await?;
                if name.ends_with(".yml") || name.ends_with(".yaml") {
                    api.to_yaml().map_err(Error::new)
                } else {
                    api.to_pretty_json().map_err(Error::new)
                }
            }
            None => Err(anyhow!("Invalid file name")),
        }?;

        match fs::write(self.file, doc) {
            Ok(_) => Ok(ExitCode::SUCCESS),
            Err(e) => Err(e.into()),
        }
    }
}
