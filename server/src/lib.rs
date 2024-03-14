#![allow(unused)]
use crate::server::{importer, read};
use actix_web::web;
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
use trustify_infrastructure::tracing::Tracing;
use trustify_infrastructure::{Infrastructure, InfrastructureConfig, InitContext, Metrics};

pub mod server;

/// Run the API server
#[derive(clap::Args, Debug)]
pub struct Run {
    #[command(flatten)]
    pub database: Database,

    #[arg(long, env)]
    pub bootstrap: bool,

    #[arg(long, env)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub http: HttpServerConfig<Huevos>,
}

const SERVICE_ID: &str = "huevos";

struct InitData {
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
    state: Arc<AppState>,
    http: HttpServerConfig<Huevos>,
    tracing: Tracing,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        // logging is only active once the infrastructure run method has been called
        Infrastructure::from(self.infra.clone())
            .run(
                SERVICE_ID,
                { |context| async move { InitData::new(context, self).await } },
                |context| async move { context.init_data.run(&context.metrics).await },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}

impl InitData {
    async fn new(context: InitContext, run: Run) -> anyhow::Result<Self> {
        let (authn, authz) = run.auth.split(run.devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> =
            Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        let system = match run.bootstrap {
            true => {
                Graph::bootstrap(
                    &run.database.username,
                    &run.database.password,
                    &run.database.host,
                    run.database.port,
                    &run.database.name,
                    DbStrategy::External,
                )
                .await?
            }
            false => Graph::with_external_config(&run.database).await?,
        };

        let state = Arc::new(AppState { system });

        let check = Local::spawn_periodic("no database connection", Duration::from_secs(1), {
            let state = state.clone();
            move || {
                let state = state.clone();
                async move { state.system.ping().await.is_ok() }
            }
        })?;

        context.health.readiness.register("database", check).await;

        Ok(InitData {
            authenticator,
            authorizer,
            state,
            http: run.http,
            tracing: run.infra.tracing,
        })
    }

    async fn run(self, metrics: &Metrics) -> anyhow::Result<()> {
        let graph = self.state.system.clone();

        let http = HttpServerBuilder::try_from(self.http)?
            .tracing(self.tracing)
            .metrics(metrics.registry().clone(), SERVICE_ID)
            .default_authenticator(self.authenticator)
            .authorizer(self.authorizer.clone())
            .configure(move |svc| {
                svc.app_data(web::Data::from(self.state.clone()))
                    .configure(configure)
                    .configure(|svc| importer::configure(svc, graph.clone()));
            });

        http.run().await
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
