use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    nest(
        (path = crate::advisory::endpoints::CONTEXT_PATH, api = crate::advisory::endpoints::ApiDoc),
        (path = crate::ai::endpoints::CONTEXT_PATH, api = crate::ai::endpoints::ApiDoc),
        (path = crate::license::endpoints::CONTEXT_PATH, api = crate::license::endpoints::ApiDoc),
        (path = crate::organization::endpoints::CONTEXT_PATH, api = crate::organization::endpoints::ApiDoc),
        (path = crate::purl::endpoints::CONTEXT_PATH, api = crate::purl::endpoints::ApiDoc),
        (path = crate::product::endpoints::CONTEXT_PATH, api = crate::product::endpoints::ApiDoc),
        (path = crate::sbom::endpoints::CONTEXT_PATH, api = crate::sbom::endpoints::ApiDoc),
        (path = crate::vulnerability::endpoints::CONTEXT_PATH, api = crate::vulnerability::endpoints::ApiDoc),
        (path = crate::weakness::endpoints::CONTEXT_PATH, api = crate::weakness::endpoints::ApiDoc),
    ),
    tags(),
)]
pub struct ApiDoc;
