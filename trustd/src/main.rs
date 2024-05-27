use clap::Parser;
use sample_data::sample_data;
use std::env;
use std::process::{ExitCode, Termination};
use tokio::task::{spawn_local, LocalSet};

mod db;
mod sample_data;

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Run the API server
    Api(trustify_server::Run),
    /// Manage the database
    Db(db::Run),
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
    pub(crate) command: Option<Command>,
}

impl Trustd {
    async fn run(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Some(Command::Api(run)) => run.run().await,
            Some(Command::Db(run)) => run.run().await,
            None => pm_mode().await,
        }
    }
}

// Project Manager Mode
async fn pm_mode() -> anyhow::Result<ExitCode> {
    let Some(Command::Db(mut db)) = Trustd::parse_from(["trustd", "db", "migrate"]).command else {
        unreachable!()
    };

    let postgres = db.start().await?;
    let database = db.database.clone();

    if !postgres.database_exists(&db.database.name).await? {
        db.command = db::Command::Create;
    }
    db.run().await?;

    // after we have the database structure, add some sample data
    sample_data(&database).await?;

    let api = Trustd::parse_from([
        "trustd",
        "api",
        #[cfg(feature = "garage-door")]
        "--embedded-oidc",
        "--db-port",
        &postgres.settings().port.to_string(),
    ]);

    LocalSet::new()
        .run_until(async { spawn_local(api.run()).await? })
        .await
}

#[tokio::main]
async fn main() -> impl Termination {
    match Trustd::parse().run().await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("Error: {err}");
            for (n, err) in err.chain().skip(1).enumerate() {
                if n == 0 {
                    eprintln!("Caused by:");
                }
                eprintln!("\t{err}");
            }
            ExitCode::FAILURE
        }
    }
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
