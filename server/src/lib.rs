#![allow(unused)]
use actix_web::body::MessageBody;
use actix_web::web;
use futures::FutureExt;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use trustify_auth::auth::AuthConfigArguments;
use trustify_auth::authenticator::Authenticator;
use trustify_auth::authorizer::Authorizer;
use trustify_common::config::Database;
use trustify_common::db;
use trustify_infrastructure::app::http::{HttpServerBuilder, HttpServerConfig};
use trustify_infrastructure::endpoint::Huevos;
use trustify_infrastructure::health::checks::{Local, Probe};
use trustify_infrastructure::tracing::Tracing;
use trustify_infrastructure::{Infrastructure, InfrastructureConfig, InitContext, Metrics};
use trustify_module_graph::graph::Graph;
use trustify_module_importer::server::importer;

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
    graph: Arc<Graph>,
    db: db::Database,
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

        let db = db::Database::with_external_config(&run.database, run.bootstrap).await?;
        let graph = Graph::new(db.clone());

        let check = Local::spawn_periodic("no database connection", Duration::from_secs(1), {
            let db = db.clone();
            move || {
                let db = db.clone();
                async move { db.ping().await.is_ok() }
            }
        })?;

        context.health.readiness.register("database", check).await;

        Ok(InitData {
            authenticator,
            authorizer,
            graph: Arc::new(graph),
            db,
            http: run.http,
            tracing: run.infra.tracing,
        })
    }

    async fn run(self, metrics: &Metrics) -> anyhow::Result<()> {
        let graph = self.graph.clone();
        let db = self.db.clone();

        let http = HttpServerBuilder::try_from(self.http)?
            .tracing(self.tracing)
            .metrics(metrics.registry().clone(), SERVICE_ID)
            .default_authenticator(self.authenticator)
            .authorizer(self.authorizer.clone())
            .configure(move |svc| {
                svc.app_data(web::Data::from(self.graph.clone()))
                    .configure(|svc| {
                        trustify_module_graph::endpoints::configure(svc);
                        trustify_module_importer::endpoints::configure(svc, db.clone());
                        trustify_module_ingestor::endpoints::configure(svc);
                    });
            });

        let http = async { http.run().await }.boxed_local();
        let importer = async { importer(self.db).await }.boxed_local();

        let (result, _, _) = futures::future::select_all([http, importer]).await;

        log::info!("one of the server tasks returned, exiting");

        result
    }
}
