#[cfg(test)]
mod test;

use crate::ai::model::{AiFlags, AiTool, ChatState};
use crate::ai::service::AiService;
use crate::Error;
use actix_http::header;
use actix_web::{get, post, web, HttpResponse, Responder};
use itertools::Itertools;
use trustify_common::db::Database;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let service = AiService::new(db.clone());
    config
        .app_data(web::Data::new(service))
        .service(completions)
        .service(flags)
        .service(tools)
        .service(tool_call);
}

#[utoipa::path(
    tag = "ai",
    operation_id = "completions",
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

#[utoipa::path(
    tag = "ai",
    operation_id = "aiFlags",
    responses(
        (status = 200, description = "The resulting Flags", body = AiFlags),
        (status = 404, description = "The AI service is not enabled")
    )
)]
#[get("/v1/ai/flags")]
// Gets the flags for the AI service
pub async fn flags(service: web::Data<AiService>) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(AiFlags {
        completions: service.completions_enabled(),
    }))
}

#[utoipa::path(
    tag = "ai",
    operation_id = "aiTools",
    responses(
        (status = 200, description = "The resulting list of tools", body = Vec<AiTool>),
        (status = 404, description = "The AI service is not enabled")
    )
)]
#[get("/v1/ai/tools")]
// Gets the list of tools that are available to assist AI services.
pub async fn tools(service: web::Data<AiService>) -> actix_web::Result<impl Responder> {
    let tools = &service
        .tools
        .iter()
        .map(|tool| AiTool {
            name: tool.name(),
            description: tool.description(),
            parameters: tool.parameters(),
        })
        .collect_vec();
    Ok(HttpResponse::Ok().json(tools))
}

#[utoipa::path(
    tag = "ai",
    operation_id = "aiToolCall",
    request_body = serde_json::Value,
    params(
        ("name", Path, description = "Name of the tool to call")
    ),
    responses(
        (status = 200, description = "The result of the tool call", body = String, content_type = "text/plain"),
        (status = 400, description = "The tool request was invalid"),
        (status = 404, description = "The tool was not found")
    )
)]
#[post("/v1/ai/tools/{name}")]
pub async fn tool_call(
    service: web::Data<AiService>,
    name: web::Path<String>,
    request: web::Json<serde_json::Value>,
) -> actix_web::Result<impl Responder> {
    let tool = service
        .tools
        .iter()
        .find(|tool| tool.name() == name.clone())
        .ok_or_else(|| actix_web::error::ErrorNotFound("Tool not found"))?;

    let result = tool
        .run(request.clone())
        .await
        .map_err(|e| Error::BadRequest(e.to_string()))?;

    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .body(result))
}
