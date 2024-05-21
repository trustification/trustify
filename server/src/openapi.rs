use utoipa::openapi::security::{OpenIdConnect, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(paths(), components(), tags())]
pub struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();

    doc.merge(trustify_module_importer::endpoints::ApiDoc::openapi());
    doc.merge(trustify_module_fundamental::openapi());

    doc
}
