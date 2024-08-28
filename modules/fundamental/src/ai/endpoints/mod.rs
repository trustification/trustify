#[cfg(test)]
mod test;

use crate::ai::model::ChatState;
use crate::ai::service::AiService;
use actix_web::{post, web, HttpResponse, Responder};
use trustify_common::db::Database;
use utoipa::OpenApi;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let service = AiService::new(db.clone());
    config
        .app_data(web::Data::new(service))
        .service(completions);
}

#[derive(OpenApi)]
#[openapi(
    paths(completions,),
    components(schemas(
        crate::ai::model::ChatState,
        crate::ai::model::ChatMessage,
        crate::ai::model::MessageType,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "ai",
    operation_id = "completions",
    context_path = "/api",
    request_body = ChatState,
    responses(
        (status = 200, description = "The resulting completion", body = ChatState),
        (status = 400, description = "The request was invalid"),
        (status = 404, description = "The AI service is not enabled")
    )
)]
#[post("/v1/ai/completions")]
pub async fn completions(
    service: web::Data<AiService>,
    request: web::Json<ChatState>,
) -> actix_web::Result<impl Responder> {
    let response = service.completions(&request, ()).await?;
    Ok(HttpResponse::Ok().json(response))
}
