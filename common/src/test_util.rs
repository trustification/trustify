use crate::config::Database;
use crate::db;
use std::sync::Arc;

pub async fn bootstrap_system(name: &str) -> Result<db::Database, anyhow::Error> {
    db::Database::with_external_config(
        &Database {
            username: "postgres".to_string(),
            password: "eggs".to_string(),
            host: "localhost".to_string(),
            port: 5432,
            name: name.to_string(),
        },
        true,
    )
    .await
}
