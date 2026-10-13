use clap::Parser;
use sea_orm_migration::prelude::*;
use trustify_module_storage::config::StorageConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let storage = StorageConfig::parse().into_storage(false).await?;
    cli::run_cli(migration::Migrator::new(storage, ())).await;
    Ok(())
}
