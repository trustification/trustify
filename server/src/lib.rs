#![allow(unused)]

use crate::server::read;
use actix_web::web;
use huevos_api::system::InnerSystem;
use std::process::ExitCode;

pub mod server;

/// Run the API server
#[derive(clap::Args, Debug)]
pub struct Run {}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        todo!();

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
    use std::sync::Arc;
    use huevos_api::system::InnerSystem;

    pub async fn bootstrap_system(name: &str) -> Result<Arc<InnerSystem>, anyhow::Error> {
        InnerSystem::bootstrap("postgres", "eggs", "localhost", name).await
    }
}
