use postgresql_embedded::PostgreSQL;
use std::env;
use std::fs::create_dir_all;
use std::process::ExitCode;
use std::time::Duration;
use trustify_common::config::Database;
use trustify_common::db;

#[derive(clap::Args, Debug)]
pub struct Run {
    #[command(subcommand)]
    pub(crate) command: Command,
    #[command(flatten)]
    pub(crate) database: Database,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Create,
    Migrate,
    Refresh,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        use Command::*;
        match self.command {
            Create => self.config(db::CreationMode::Bootstrap).await,
            Migrate => self.config(db::CreationMode::Default).await,
            Refresh => self.config(db::CreationMode::RefreshSchema).await,
        }
    }

    async fn config(self, mode: db::CreationMode) -> anyhow::Result<ExitCode> {
        match db::Database::with_external_config(&self.database, mode).await {
            Ok(_) => Ok(ExitCode::SUCCESS),
            Err(e) => Err(e),
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<PostgreSQL> {
        println!("setting up managed DB");
        use postgresql_embedded::Settings;

        let current_dir = env::current_dir()?;
        let work_dir = current_dir.join(".trustify");
        let db_dir = work_dir.join("postgres");
        let data_dir = work_dir.join("data");
        create_dir_all(&data_dir)?;
        let settings = Settings {
            username: self.database.username.clone(),
            password: self.database.password.clone(),
            temporary: false,
            installation_dir: db_dir.clone(),
            timeout: Some(Duration::from_secs(30)),
            data_dir,
            ..Default::default()
        };
        let mut postgresql = PostgreSQL::new(PostgreSQL::default_version(), settings);
        postgresql.setup().await?;
        postgresql.start().await?;

        let port = postgresql.settings().port;
        self.database.port = port;

        println!("postgresql installed under {:?}", db_dir);
        println!("running on port {}", port);

        Ok(postgresql)
    }
}
