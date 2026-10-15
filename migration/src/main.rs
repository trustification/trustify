use clap::Parser;
use migration::data::Options;
use sea_orm::{ConnectOptions, Database};
use sea_orm_cli::MigrateSubcommands;
use sea_orm_migration::cli;
use trustify_module_storage::config::StorageConfig;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    #[arg(global = true, short = 'u', long, env = "DATABASE_URL")]
    database_url: Option<String>,

    #[arg(global = true, short = 's', long, env = "DATABASE_SCHEMA")]
    database_schema: Option<String>,

    #[command(subcommand)]
    command: Option<MigrateSubcommands>,

    #[command(flatten)]
    storage: StorageConfig,

    #[command(flatten)]
    options: Options,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let storage = cli.storage.into_storage(false).await?;
    let migrator = migration::Migrator::new(storage, cli.options);

    let url = cli
        .database_url
        .ok_or_else(|| anyhow::anyhow!("Environment variable 'DATABASE_URL' not set"))?;
    let schema = cli.database_schema.unwrap_or_else(|| "public".into());

    let connect_options = ConnectOptions::new(url)
        .set_schema_search_path(schema)
        .to_owned();

    let db = Database::connect(connect_options).await?;

    cli::run_migrate(migrator, &db, cli.command, cli.verbose)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}
