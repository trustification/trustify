use clap::Parser;
use std::process::{ExitCode, Termination};

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Importer(trustify_importer::ImporterCommand),
    Server(trustify_server::Run),
}

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "trustd",
    long_about = None
)]
pub struct Trustd {
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Trustd {
    async fn run(self) -> ExitCode {
        match self.run_command().await {
            Ok(code) => code,
            Err(err) => {
                log::info!("Error: {err}");
                for (n, err) in err.chain().skip(1).enumerate() {
                    if n == 0 {
                        log::info!("Caused by:");
                    }
                    log::info!("\t{err}");
                }

                ExitCode::FAILURE
            }
        }
    }

    async fn run_command(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Importer(run) => run.run().await,
            Command::Server(run) => run.run().await,
        }
    }
}

#[tokio::main]
async fn main() -> impl Termination {
    Trustd::parse().run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Trustd::command().debug_assert();
    }
}
