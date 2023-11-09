#![allow(unused)]

use crate::server::read;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use huevos_api::system::InnerSystem;
use huevos_common::config::Database;
use std::process::ExitCode;
use std::sync::Arc;

pub mod server;

/// Run the API server
#[derive(clap::Args, Debug)]
pub struct Run {
    #[arg(short, long, env, default_value = "[::1]:8080")]
    pub bind_addr: String,

    #[command(flatten)]
    pub database: Database,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let app_state = Arc::new(AppState {
            system: InnerSystem::with_config(&self.database).await?,
        });

        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::from(app_state.clone()))
                .wrap(Logger::default())
                .configure(configure)
        })
        .bind(self.bind_addr)?
        .run()
        .await?;

        Ok(ExitCode::SUCCESS)
    }
}

pub struct AppState {
    pub system: InnerSystem,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(read::package::dependencies)
        .service(read::package::variants);
}

#[cfg(test)]
mod test_util {
    use huevos_api::system::InnerSystem;
    use std::sync::Arc;

    pub async fn bootstrap_system(name: &str) -> Result<Arc<InnerSystem>, anyhow::Error> {
        InnerSystem::bootstrap("postgres", "eggs", "localhost", name).await
    }
}
