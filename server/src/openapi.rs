use utoipa::{
    openapi::security::{OpenIdConnect, SecurityScheme},
    Modify, OpenApi,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Trustify",
        description = "Software Supply-Chain Security API",
        license(
            name = "Apache License, Version 2.0",
            identifier = "Apache-2.0",
        )
    ),
    nest(
        (path = trustify_module_analysis::endpoints::CONTEXT_PATH, api = trustify_module_analysis::endpoints::ApiDoc),
        (path = trustify_module_importer::endpoints::CONTEXT_PATH, api = trustify_module_importer::endpoints::ApiDoc),
        (path = trustify_module_ingestor::endpoints::CONTEXT_PATH, api = trustify_module_ingestor::endpoints::ApiDoc),
    ),
)]
pub struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();

    doc.merge(crate::endpoints::ApiDoc::openapi());
    doc.merge(trustify_module_fundamental::ApiDoc::openapi());

    doc
}
