#![allow(unused)]

use crate::server::read;
use crate::server::Error::System;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use trustify_api::graph::{DbStrategy, Graph};
use trustify_auth::auth::AuthConfigArguments;
use trustify_auth::authenticator::Authenticator;
use trustify_auth::authorizer::Authorizer;
use trustify_common::config::Database;
use trustify_infrastructure::app::http::{HttpServerBuilder, HttpServerConfig};
use trustify_infrastructure::endpoint::Huevos;
use trustify_infrastructure::health::checks::{Local, Probe};
use trustify_infrastructure::{Infrastructure, InfrastructureConfig};

pub mod server;

/// Run the API server
#[derive(clap::Args, Debug)]
pub struct Run {
    #[arg(short, long, env, default_value = "[::1]:8080")]
    pub bind_addr: String,

    #[command(flatten)]
    pub database: Database,

    #[arg(long, env)]
    pub bootstrap: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub http: HttpServerConfig<Huevos>,
}

const SERVICE_ID: &str = "huevos";

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let tracing = self.infra.tracing;

        let (authn, authz) = self.auth.split(self.bootstrap)?.unzip();
        let authenticator: Option<Arc<Authenticator>> =
            Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        let system = match self.bootstrap {
            true => {
                Graph::bootstrap(
                    &self.database.username,
                    &self.database.password,
                    &self.database.host,
                    self.database.port,
                    &self.database.name,
                    DbStrategy::External,
                )
                .await?
            }
            false => Graph::with_external_config(&self.database).await?,
        };

        let app_state = Arc::new(AppState { system });

        Infrastructure::from(self.infra)
            .run(
                SERVICE_ID,
                {
                    let state = app_state.clone();
                    |context| async move {
                        let state = state.clone();
                        let check = Local::spawn_periodic(
                            "no database connection",
                            Duration::from_secs(1),
                            move || {
                                let state = state.clone();
                                async move { state.system.ping().await.is_ok() }
                            },
                        )?;

                        context.health.readiness.register("database", check).await;

                        Ok(())
                    }
                },
                |context| async move {
                    let http = HttpServerBuilder::try_from(self.http)?
                        .tracing(tracing)
                        .metrics(context.metrics.registry().clone(), SERVICE_ID)
                        .authorizer(authorizer.clone())
                        .configure(move |svc| {
                            svc.app_data(web::Data::from(app_state.clone()))
                                .configure(configure);
                        });

                    http.run().await
                },
            )
            .await;

        Ok(ExitCode::SUCCESS)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub system: Graph,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(read::package::dependencies)
        .service(read::package::variants);
}

#[cfg(test)]
mod test_util {
    use std::sync::Arc;
    use trustify_api::graph::{DbStrategy, Graph};

    pub async fn bootstrap_system(name: &str) -> Result<Arc<Graph>, anyhow::Error> {
        Graph::bootstrap(
            "postgres",
            "eggs",
            "localhost",
            None,
            name,
            DbStrategy::External,
        )
        .await
        .map(Arc::new)
    }
}
