use clap::Parser;
use std::env;
use std::process::{ExitCode, Termination};
use std::time::Duration;
use tokio::task::{spawn_local, LocalSet};
use trustify_common::config::Database;
use trustify_module_importer::model::{
    CommonImporter, CsafImporter, ImporterConfiguration, SbomImporter,
};
use trustify_module_importer::service::{Error, ImporterService};
use url::Url;

mod db;

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
        "--auth-disabled",
        "--db-port",
        &postgres.settings().port.to_string(),
    ]);

    LocalSet::new()
        .run_until(async { spawn_local(api.run()).await? })
        .await
}

async fn sample_data(db: &Database) -> anyhow::Result<()> {
    let db = trustify_common::db::Database::new(db).await?;

    let importer = ImporterService::new(db);
    importer
        .create(
            "redhat-sbom".into(),
            ImporterConfiguration::Sbom(SbomImporter {
                common: CommonImporter {
                    disabled: true,
                    period: Duration::from_secs(300),
                    description: Some("All Red Hat SBOMs".into())
                },
                source: "https://access.redhat.com/security/data/sbom/beta/".to_string(),
                keys: vec![
                    Url::parse("https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4")?
                ],
                v3_signatures: true,
                only_patterns: vec![],
            }),
        )
        .await.or_else(|err|match err {
            Error::AlreadyExists(_) =>Ok(()),
            err => Err(err)
        })?;
    importer
        .create(
            "redhat-csaf-vex-2024".into(),
            ImporterConfiguration::Csaf(CsafImporter {
                common: CommonImporter {
                    disabled: true,
                    period: Duration::from_secs(300),
                    description: Some("Red Hat VEX files from 2024".into()),
                },
                source: "redhat.com".to_string(),
                v3_signatures: true,
                only_patterns: vec!["^cve-2024-".into()],
            }),
        )
        .await
        .or_else(|err| match err {
            Error::AlreadyExists(_) => Ok(()),
            err => Err(err),
        })?;

    Ok(())
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
