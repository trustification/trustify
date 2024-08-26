use utoipa::openapi::{Object, RefOr, Schema, SchemaType};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(paths(), components(), tags())]
pub struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();

    doc.merge(crate::advisory::endpoints::ApiDoc::openapi());
    doc.merge(crate::license::endpoints::ApiDoc::openapi());
    doc.merge(crate::organization::endpoints::ApiDoc::openapi());
    doc.merge(crate::purl::endpoints::ApiDoc::openapi());
    doc.merge(crate::product::endpoints::ApiDoc::openapi());
    doc.merge(crate::sbom::endpoints::ApiDoc::openapi());
    doc.merge(crate::vulnerability::endpoints::ApiDoc::openapi());
    doc.merge(crate::weakness::endpoints::ApiDoc::openapi());

    if let Some(components) = doc.components.as_mut() {
        let mut obj = Object::with_type(SchemaType::String);
        obj.description = Some("a UUID".to_string());
        components
            .schemas
            .insert("Uuid".to_string(), RefOr::T(Schema::Object(obj)));
    }

    doc
}
