use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(paths(), components(), tags())]
pub struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();

    doc.merge(crate::advisory::endpoints::ApiDoc::openapi());
    doc.merge(crate::organization::endpoints::ApiDoc::openapi());
    doc.merge(crate::package::endpoints::ApiDoc::openapi());
    doc.merge(crate::sbom::endpoints::ApiDoc::openapi());
    doc.merge(crate::vulnerability::endpoints::ApiDoc::openapi());

    doc
}
