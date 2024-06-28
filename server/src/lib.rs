#![allow(unused)]
#![recursion_limit = "256"]

#[cfg(feature = "garage-door")]
mod embedded_oidc;
mod openapi;
mod sample_data;

pub use sample_data::sample_data;

#[cfg(feature = "ui")]
use trustify_module_ui::UI;

use actix_web::{
    body::MessageBody,
    dev::{ConnectionInfo, Url},
    error::UrlGenerationError,
    get, middleware, web,
    web::Json,
    HttpRequest, Responder, Result,
};
use anyhow::Context;
use bytesize::ByteSize;
use futures::{FutureExt, StreamExt};
use std::fmt::Display;
use std::fs::create_dir_all;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use trustify_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    devmode::{FRONTEND_CLIENT_ID, ISSUER_URL, PUBLIC_CLIENT_IDS},
    swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc, SwaggerUiOidcConfig},
};
use trustify_common::{
    config::{Database, StorageConfig},
    db,
};
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
use trustify_module_storage::{service::dispatch::DispatchBackend, service::fs::FileSystemBackend};
use trustify_module_ui::endpoints::UiResources;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Run the API server
#[derive(clap::Args, Debug)]
pub struct Run {
    #[arg(long, env)]
    pub devmode: bool,

    #[arg(long, env)]
    pub sample_data: bool,

    /// Enable the embedded OIDC server (WARNING: this is insecure and should only be used for demos)
    #[cfg(feature = "garage-door")]
    #[arg(long, env)]
    pub embedded_oidc: bool,

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

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub http: HttpServerConfig<Trustify>,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[cfg(feature = "ui")]
    #[command(flatten)]
    pub ui: UiConfig,
}

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "UI")]
#[group(id = "ui")]
pub struct UiConfig {
    /// Issuer URL used by the UI
    #[arg(id = "ui-issuer-url", long, env = "UI_ISSUER_URL", default_value_t = ISSUER_URL.to_string())]
    pub issuer_url: String,
    /// Client ID used by the UI
    #[arg(id = "ui-client-id", long, env ="UI_CLIENT_ID", default_value_t = FRONTEND_CLIENT_ID.to_string())]
    pub client_id: String,
    /// Scopes to request
    #[arg(id = "ui-scope", long, env = "UI_SCOPE", default_value = "openid")]
    pub scope: String,
}

const SERVICE_ID: &str = "trustify";

struct InitData {
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
    graph: Arc<Graph>,
    db: db::Database,
    storage: DispatchBackend,
    http: HttpServerConfig<Trustify>,
    tracing: Tracing,
    swagger_oidc: Option<Arc<SwaggerUiOidc>>,
    #[cfg(feature = "garage-door")]
    embedded_oidc: Option<embedded_oidc::EmbeddedOidc>,
    #[cfg(feature = "ui")]
    ui: UI,
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
        // The devmode for the auth parts. This allows us to enable devmode for auth, but not
        // for other parts.
        #[allow(unused_mut)]
        let mut auth_devmode = run.devmode;

        #[cfg(feature = "garage-door")]
        let embedded_oidc = {
            // When running with the embedded OIDC server, re-use devmode. Running the embedded OIDC
            // without devmode doesn't make any sense. However, the pm-mode doesn't know about
            // devmode. Also, enabling devmode might trigger other logic.
            auth_devmode = true;
            embedded_oidc::spawn(run.embedded_oidc).await?
        };

        let (authn, authz) = run.auth.split(auth_devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> =
            Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        let swagger_oidc = match authenticator.is_some() {
            true => SwaggerUiOidc::from_devmode_or_config(auth_devmode, run.swagger_ui_oidc)
                .await?
                .map(Arc::new),
            false => None,
        };

        let db = db::Database::new(&run.database).await?;

        if run.devmode {
            db.migrate().await?;
        }

        if run.devmode || run.sample_data {
            sample_data(db.clone()).await?;
        }

        let graph = Graph::new(db.clone());

        let check = Local::spawn_periodic("no database connection", Duration::from_secs(1), {
            let db = db.clone();
            move || {
                let db = db.clone();
                async move { db.ping().await.is_ok() }
            }
        })?;

        context.health.readiness.register("database", check).await;

        let storage = run
            .storage
            .fs_path
            .as_ref()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("./.trustify/storage"));
        if run.devmode {
            create_dir_all(&storage).context(format!(
                "Failed to create filesystem storage directory: {:?}",
                run.storage.fs_path
            ))?;
        }

        let storage = DispatchBackend::Filesystem(FileSystemBackend::new(storage).await?);

        #[cfg(feature = "ui")]
        let ui = UI {
            // TODO: where/how should we configure these details?
            version: env!("CARGO_PKG_VERSION").to_string(),
            auth_required: authenticator.is_some().to_string(),
            oidc_server_url: run.ui.issuer_url,
            oidc_client_id: run.ui.client_id,
            oidc_scope: run.ui.scope,
            analytics_enabled: String::from("false"),
            analytics_write_key: String::from(""),
        };

        Ok(InitData {
            authenticator,
            authorizer,
            graph: Arc::new(graph),
            db,
            http: run.http,
            tracing: run.infra.tracing,
            swagger_oidc,
            storage,
            #[cfg(feature = "garage-door")]
            embedded_oidc,
            #[cfg(feature = "ui")]
            ui,
            working_dir: run.working_dir,
        })
    }

    async fn run(mut self, metrics: &Metrics) -> anyhow::Result<()> {
        let swagger_oidc = self.swagger_oidc;
        let ui = UiResources::new(&self.ui)?;

        let limit = ByteSize::gb(1).as_u64() as usize;

        let http = {
            let graph = self.graph.clone();
            let db = self.db.clone();
            let storage = self.storage.clone();

            HttpServerBuilder::try_from(self.http)?
                .tracing(self.tracing)
                .metrics(metrics.registry().clone(), SERVICE_ID)
                .authorizer(self.authorizer)
                .configure(move |svc| {
                    svc.app_data(web::PayloadConfig::default().limit(limit))
                        .service(swagger_ui_with_auth(
                            openapi::openapi(),
                            swagger_oidc.clone(),
                        ))
                        .service(web::redirect("/openapi", "/openapi/"));
                    svc.service(
                        web::scope("/graphql")
                            .wrap(middleware::NormalizePath::new(
                                middleware::TrailingSlash::Always,
                            ))
                            .wrap(new_auth(self.authenticator.clone()))
                            .configure(|svc| {
                                trustify_module_graphql::endpoints::configure(
                                    svc,
                                    db.clone(),
                                    graph.clone(),
                                );
                                trustify_module_graphql::endpoints::configure_graphiql(svc);
                            }),
                    );
                    svc.app_data(web::Data::from(self.graph.clone()))
                        .service(
                            web::scope("/api")
                                .wrap(new_auth(self.authenticator.clone()))
                                .configure(|svc| {
                                    trustify_module_importer::endpoints::configure(svc, db.clone());

                                    trustify_module_fundamental::endpoints::configure(
                                        svc,
                                        db.clone(),
                                        storage.clone(),
                                    );
                                }),
                        )
                        .configure(|svc| {
                            // I think the UI must come last due to
                            // its use of `resolve_not_found_to`
                            #[cfg(feature = "ui")]
                            trustify_module_ui::endpoints::configure(svc, &ui);
                        });
                })
        };

        let http = async { http.run().await }.boxed_local();
        let importer =
            async { importer(self.db, self.storage, self.working_dir).await }.boxed_local();

        let mut tasks = vec![http, importer];

        // track the embedded OIDC server task
        #[cfg(feature = "garage-door")]
        if let Some(embedded_oidc) = self.embedded_oidc.take() {
            tasks.push(
                async move {
                    embedded_oidc.0.await?;
                    Ok::<_, anyhow::Error>(())
                }
                .boxed_local(),
            );
        }

        let (result, _, _) = futures::future::select_all(tasks).await;

        log::info!("one of the server tasks returned, exiting: {result:?}");

        result
    }
}

fn build_url(ci: &ConnectionInfo, path: impl Display) -> Option<url::Url> {
    url::Url::parse(&format!(
        "{scheme}://{host}{path}",
        scheme = ci.scheme(),
        host = ci.host()
    ))
    .ok()
}

#[get("/")]
async fn index(ci: ConnectionInfo) -> Result<Json<Vec<url::Url>>, UrlGenerationError> {
    let mut result = vec![];

    result.extend(build_url(&ci, "/"));
    result.extend(build_url(&ci, "/openapi.json"));
    result.extend(build_url(&ci, "/openapi/"));

    Ok(Json(result))
}
