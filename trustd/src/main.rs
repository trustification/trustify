use clap::Parser;
use postgresql_embedded::PostgreSQL;
use std::env;
use std::process::{ExitCode, Termination};
use tokio::task::JoinSet;
use trustify_auth::auth::AuthConfigArguments;
use trustify_auth::swagger_ui::SwaggerUiOidcConfig;
use trustify_common::config::{Database, DbStrategy, StorageConfig};
use trustify_common::db::CreationMode;
use trustify_infrastructure::app::http::HttpServerConfig;
use trustify_infrastructure::endpoint::Trustify;
use trustify_infrastructure::InfrastructureConfig;

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
pub enum Command {}

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

    /// The database creation mode
    #[arg(long, env, value_enum, default_value_t = CreationMode::Default)]
    pub creation: CreationMode,

    #[arg(long, env, default_value_t = true, requires = "auth")]
    pub with_http: bool,

    #[arg(long, env)]
    pub devmode: bool,

    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub database: Database,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub http: HttpServerConfig<Trustify>,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,
}

impl Trustd {
    async fn run(self) -> ExitCode {
        match self.run_command().await {
            Ok(code) => code,
            Err(err) => {
                log::error!("Error: {err}");
                for (n, err) in err.chain().skip(1).enumerate() {
                    if n == 0 {
                        log::error!("Caused by:");
                    }
                    log::error!("\t{err}");
                }

                ExitCode::FAILURE
            }
        }
    }

    async fn run_command(mut self) -> anyhow::Result<ExitCode> {
        // to keep in scope while running.
        let mut managed_db = None;

        if matches!(self.database.db_strategy, DbStrategy::Managed) {
            println!("setting up managed DB");
            use postgresql_embedded::Settings;

            let current_dir = env::current_dir()?;
            let work_dir = current_dir.join(".trustify");
            let db_dir = work_dir.join("postgres");
            let settings = Settings {
                username: self.database.username.clone(),
                password: self.database.password.clone(),
                temporary: false,
                installation_dir: db_dir.clone(),
                ..Default::default()
            };

            let mut postgresql = PostgreSQL::new(PostgreSQL::default_version(), settings);
            postgresql.setup().await?;
            postgresql.start().await?;

            let port = postgresql.settings().port;
            self.database.port = port;
            self.creation = CreationMode::Bootstrap;

            managed_db.replace(postgresql);

            println!("postgresql installed under {:?}", db_dir);
            println!("running on port {}", port);
        }

        let mut handles = JoinSet::new();

        if self.with_http {
            let http = trustify_server::Run {
                database: self.database.clone(),
                storage: self.storage.clone(),
                creation: self.creation,
                devmode: self.devmode,
                infra: self.infra.clone(),
                auth: self.auth.clone(),
                http: self.http.clone(),
                swagger_ui_oidc: self.swagger_ui_oidc.clone(),
            };

            handles.spawn_local(http.run());
        }

        while let Some(result) = handles.join_next().await {
            match result {
                Ok(result) => match result {
                    Ok(_) => {}
                    Err(err) => {
                        log::error!("error {:?}", err);
                    }
                },
                Err(err) => {
                    log::error!("fundamental error {:?}", err);
                }
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}

#[actix_web::main]
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
