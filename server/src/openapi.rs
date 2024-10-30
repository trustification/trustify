use crate::{configure, default_openapi_info, Config, ModuleConfig};
use actix_web::App;
use trustify_common::{config::Database, db};
use trustify_module_storage::service::{dispatch::DispatchBackend, fs::FileSystemBackend};
use utoipa::{
    openapi::security::{OpenIdConnect, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_actix_web::AppExt;

pub async fn create_openapi() -> anyhow::Result<utoipa::openapi::OpenApi> {
    let (db, postgresql) = db::embedded::create().await?;
    let (storage, _temp) = FileSystemBackend::for_test().await?;

    let (_, mut openapi) = App::new()
        .into_utoipa_app()
        .configure(|svc| {
            configure(
                svc,
                Config {
                    config: ModuleConfig::default(),
                    db,
                    storage: storage.into(),
                    auth: None,
                    with_graphql: true,
                },
            );
        })
        .split_for_parts();

    openapi.info = default_openapi_info();

    Ok(openapi)
}
