use utoipa::openapi::security::{OpenIdConnect, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(paths(), components(), tags())]
pub struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();

    doc.info.title = "Trustify".to_string();
    doc.info.description = Some("Software Supply-Chain Security API".to_string());
    doc.info.version = env!("CARGO_PKG_VERSION").to_string();

    doc.merge(trustify_module_importer::endpoints::ApiDoc::openapi());
    doc.merge(trustify_module_ingestor::endpoints::ApiDoc::openapi());
    doc.merge(trustify_module_fundamental::openapi());
    doc.merge(trustify_module_analysis::endpoints::ApiDoc::openapi());
    doc
}
