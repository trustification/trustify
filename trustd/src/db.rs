use postgresql_embedded::PostgreSQL;
use std::env;
use std::fs::create_dir_all;
use std::process::ExitCode;
use trustify_common::config::Database;

#[derive(clap::Args, Debug)]
pub struct Run {
    #[command(subcommand)]
    command: Command,
    #[command(flatten)]
    database: Database,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Start,
    Migrate,
    Refresh,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        use Command::*;
        match self.command {
            Start => self.start().await,
            _ => Ok(ExitCode::SUCCESS),
        }
    }

    async fn start(mut self) -> anyhow::Result<ExitCode> {
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

        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                postgresql.stop().await.unwrap();
                Ok(ExitCode::SUCCESS)
            }
            Err(err) => Err(err.into()),
        }
    }
}
