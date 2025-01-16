#[cfg(test)]
mod test;

use crate::{
    ai::{
        model::{AiFlags, AiTool, ChatMessage, ChatState, Conversation, ConversationSummary},
        service::AiService,
    },
    Error,
};
use actix_web::{
    delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    post, put, web, HttpResponse, Responder,
};
use itertools::Itertools;
use time::OffsetDateTime;
use trustify_auth::{authenticator::user::UserDetails, authorizer::Require, Ai};
use trustify_common::{
    db::{query::Query, Database},
    model::{Paginated, PaginatedResults},
};
use uuid::Uuid;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let service = AiService::new(db.clone());
    config
        .app_data(web::Data::new(service))
        .service(completions)
        .service(flags)
        .service(tools)
        .service(tool_call)
        .service(create_conversation)
        .service(update_conversation)
        .service(list_conversations)
        .service(get_conversation)
        .service(delete_conversation);
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
#[post("/v2/ai/completions")]
pub async fn completions(
    service: web::Data<AiService>,
    request: web::Json<ChatState>,
    _: Require<Ai>,
) -> actix_web::Result<impl Responder> {
    let response = service.completions(&request).await?;
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
#[get("/v2/ai/flags")]
// Gets the flags for the AI service
pub async fn flags(
    service: web::Data<AiService>,
    _: Require<Ai>,
) -> actix_web::Result<impl Responder> {
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
#[get("/v2/ai/tools")]
// Gets the list of tools that are available to assist AI services.
pub async fn tools(
    service: web::Data<AiService>,
    _: Require<Ai>,
) -> actix_web::Result<impl Responder> {
    let tools = &service
        .local_tools
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
#[post("/v2/ai/tools/{name}")]
pub async fn tool_call(
    service: web::Data<AiService>,
    name: web::Path<String>,
    request: String,
    _: Require<Ai>,
) -> actix_web::Result<impl Responder> {
    let tool = service
        .local_tools
        .iter()
        .find(|tool| tool.name() == name.clone())
        .ok_or_else(|| actix_web::error::ErrorNotFound("Tool not found"))?;

    let result = tool
        .call(request.as_str())
        .await
        .map_err(|e| Error::BadRequest(e.to_string()))?;

    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .body(result))
}

#[utoipa::path(
    tag = "ai",
    operation_id = "createConversation",
    responses(
        (status = 200, description = "The resulting conversation", body = Conversation),
        (status = 400, description = "The request was invalid"),
        (status = 404, description = "The AI service is not enabled")
    )
)]
#[post("/v2/ai/conversations")]
pub async fn create_conversation(_: Require<Ai>) -> actix_web::Result<impl Responder, Error> {
    // generate an assistant response
    let uuid = Uuid::now_v7();
    let response = Conversation {
        id: uuid,
        messages: Default::default(),
        updated_at: to_offset_date_time(uuid)?,
        seq: 0,
    };

    Ok(HttpResponse::Ok().json(response))
}

fn to_offset_date_time(uuid: Uuid) -> Result<OffsetDateTime, Error> {
    match uuid.get_timestamp() {
        Some(ts) => match OffsetDateTime::from_unix_timestamp(ts.to_unix().0 as i64) {
            Ok(ts) => Ok(ts),
            Err(e) => Err(Error::Internal(e.to_string())),
        },
        None => Err(Error::Internal("uuid generation failure".into())),
    }
}

#[utoipa::path(
    tag = "ai",
    operation_id = "updateConversation",
    params(
        ("id", Path, description = "Opaque ID of the conversation"),
        ("if-match"=Option<String>, Header, description = "The revision to update")
    ),
    request_body = Vec<ChatMessage>,
    responses(
        (status = 200, description = "The resulting conversation", body = Conversation),
        (status = 400, description = "The request was invalid"),
        (status = 404, description = "The AI service is not enabled or the conversation was not found")
    )
)]
#[put("/v2/ai/conversations/{id}")]
pub async fn update_conversation(
    service: web::Data<AiService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserDetails,
    request: web::Json<Vec<ChatMessage>>,
    _: Require<Ai>,
) -> actix_web::Result<impl Responder> {
    let user_id = user.id;
    let seq = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items
            .first()
            .and_then(|etag| etag.tag().parse::<i32>().ok()),
    };
    let conversation_id = id.into_inner();

    let (conversation, messages) = service
        .upsert_conversation(conversation_id, user_id, &request, seq, db.as_ref())
        .await?;

    let conversation = Conversation {
        id: conversation.id,
        updated_at: conversation.updated_at,
        messages,
        seq: conversation.seq,
    };

    Ok(HttpResponse::Ok().json(conversation))
}

#[utoipa::path(
    tag = "ai",
    operation_id = "listConversations",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "The resulting list of conversation summaries", body = PaginatedResults<ConversationSummary>),
        (status = 404, description = "The AI service is not enabled")
    )
)]
#[get("/v2/ai/conversations")]
// Gets the list of the user's previous conversations
pub async fn list_conversations(
    service: web::Data<AiService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    db: web::Data<Database>,
    user: UserDetails,
    _: Require<Ai>,
) -> actix_web::Result<impl Responder> {
    let user_id = user.id;

    let result = service
        .fetch_conversations(user_id, search, paginated, db.as_ref())
        .await?;

    let result = PaginatedResults {
        items: result
            .items
            .into_iter()
            .map(|c| ConversationSummary {
                id: c.id,
                summary: c.summary,
                updated_at: c.updated_at,
            })
            .collect(),
        total: result.total,
    };

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "ai",
    operation_id = "getConversation",
    params(
        ("id", Path, description = "Opaque ID of the conversation")
    ),
    responses(
        (status = 200, description = "The resulting conversation", body = Conversation, headers(
            ("etag" = String, description = "Sequence ID")
        )),
        (status = 400, description = "The request was invalid"),
        (status = 404, description = "The AI service is not enabled")
    )
)]
#[get("/v2/ai/conversations/{id}")]
pub async fn get_conversation(
    service: web::Data<AiService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    user: UserDetails,
    _: Require<Ai>,
) -> actix_web::Result<impl Responder> {
    let user_id = user.id;

    let uuid = id.into_inner();
    let conversation = service.fetch_conversation(uuid, db.as_ref()).await?;

    match conversation {
        // return an empty conversation i
        None => Ok(HttpResponse::Ok()
            .append_header((header::ETAG, ETag(EntityTag::new_strong("0".to_string()))))
            .json(Conversation {
                id: uuid,
                messages: Default::default(),
                updated_at: to_offset_date_time(uuid)?,
                seq: 0,
            })),

        // Found the conversation
        Some((conversation, internal_state)) => {
            // verify that the conversation belongs to the user
            if conversation.user_id != user_id {
                // make this error look like a not found error to avoid leaking
                // existence of the conversation
                Err(Error::NotFound("conversation not found".to_string()))?;
            }

            Ok(HttpResponse::Ok()
                .append_header((
                    header::ETAG,
                    ETag(EntityTag::new_strong(format!("{}", conversation.seq))),
                ))
                .json(Conversation {
                    id: conversation.id,
                    updated_at: conversation.updated_at,
                    messages: internal_state.chat_messages(),
                    seq: conversation.seq,
                }))
        }
    }
}

#[utoipa::path(
    tag = "ai",
    operation_id = "deleteConversation",
    params(
        ("id", Path, description = "Opaque ID of the conversation")
    ),
    responses(
        (status = 200, description = "The resulting conversation", body = Conversation),
        (status = 400, description = "The request was invalid"),
        (status = 404, description = "The AI service is not enabled or the conversation was not found")
    )
)]
#[delete("/v2/ai/conversations/{id}")]
pub async fn delete_conversation(
    service: web::Data<AiService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    user: UserDetails,
    _: Require<Ai>,
) -> actix_web::Result<impl Responder> {
    let user_id = user.id;
    let conversation_id = id.into_inner();

    let conversation = service
        .fetch_conversation(conversation_id, db.as_ref())
        .await?;

    match conversation {
        // the conversation_id might be invalid
        None => Err(Error::NotFound("conversation not found".to_string()))?,

        // Found the conversation
        Some((conversation, internal_state)) => {
            // verify that the conversation belongs to the user
            if conversation.user_id != user_id {
                // make this error look like a not found error to avoid leaking
                // existence of the conversation
                Err(Error::NotFound("conversation not found".to_string()))?;
            }

            let rows_affected = service
                .delete_conversation(conversation_id, db.as_ref())
                .await?;
            match rows_affected {
                0 => Ok(HttpResponse::NotFound().finish()),
                1 => Ok(HttpResponse::Ok().json(Conversation {
                    id: conversation.id,
                    updated_at: conversation.updated_at,
                    messages: internal_state.chat_messages(),
                    seq: conversation.seq,
                })),
                _ => Err(Error::Internal("Unexpected number of rows affected".into()))?,
            }
        }
    }
}
