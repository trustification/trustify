use crate::{endpoints, sample_data};
use actix_web::{
    body::MessageBody,
    dev::{ConnectionInfo, Url},
    error::UrlGenerationError,
    get, middleware, web,
    web::Json,
    HttpRequest, HttpResponse, Responder, Result,
};
use anyhow::Context;
use bytesize::ByteSize;
use futures::{FutureExt, StreamExt};
use std::{
    fmt::Display, fs::create_dir_all, path::PathBuf, process::ExitCode, sync::Arc, time::Duration,
};
use tokio::task::JoinHandle;
use trustify_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    devmode::{FRONTEND_CLIENT_ID, ISSUER_URL, PUBLIC_CLIENT_IDS},
    swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc, SwaggerUiOidcConfig},
};
use trustify_common::{config::Database, db, model::BinaryByteSize};
use trustify_infrastructure::{
    app::{
        http::{HttpServerBuilder, HttpServerConfig},
        new_auth,
    },
    endpoint::Trustify,
    health::checks::{Local, Probe},
    tracing::Tracing,
    Infrastructure, InfrastructureConfig, InitContext, Metrics,
};
use trustify_module_graphql::RootQuery;
use trustify_module_importer::server::importer;
use trustify_module_ingestor::graph::Graph;
use trustify_module_storage::{
    config::{StorageConfig, StorageStrategy},
    service::{dispatch::DispatchBackend, fs::FileSystemBackend, s3::S3Backend},
};
use trustify_module_ui::{endpoints::UiResources, UI};
use utoipa::openapi::{Info, License};
use utoipa::OpenApi;
use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::{Redoc, Servable};

/// Run the API server
#[derive(clap::Args, Debug)]
pub struct Run {
    /// The importer working directory
    #[arg(long, env)]
    pub working_dir: Option<PathBuf>,

    // flattened commands must go last
    //
    /// Database configuration
    #[command(flatten)]
    pub database: Database,

    /// Location of the storage
    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

const SERVICE_ID: &str = "trustify-importer";

struct InitData {
    db: db::Database,
    storage: DispatchBackend,
    tracing: Tracing,
    working_dir: Option<PathBuf>,
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
        let db = db::Database::new(&run.database).await?;

        let check = Local::spawn_periodic("no database connection", Duration::from_secs(1), {
            let db = db.clone();
            move || {
                let db = db.clone();
                async move { db.ping().await.is_ok() }
            }
        })?;

        context.health.readiness.register("database", check).await;

        let storage = match run.storage.storage_strategy {
            StorageStrategy::Fs => {
                let storage = run
                    .storage
                    .fs_path
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from("./.trustify/storage"));
                DispatchBackend::Filesystem(
                    FileSystemBackend::new(storage, run.storage.compression).await?,
                )
            }
            StorageStrategy::S3 => DispatchBackend::S3(
                S3Backend::new(run.storage.s3_config, run.storage.compression).await?,
            ),
        };

        Ok(InitData {
            db,
            tracing: run.infra.tracing,
            storage,
            working_dir: run.working_dir,
        })
    }

    async fn run(mut self, metrics: &Metrics) -> anyhow::Result<()> {
        let db = self.db;
        let storage = self.storage;

        let importer = async { importer(db, storage, self.working_dir).await }.boxed_local();

        let tasks = vec![importer];

        let (result, _, _) = futures::future::select_all(tasks).await;

        log::info!("one of the server tasks returned, exiting: {result:?}");

        result
    }
}
