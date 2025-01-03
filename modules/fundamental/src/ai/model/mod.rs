use langchain_rust::schemas::Message;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq)]
pub struct Conversation {
    pub id: Uuid,
    pub messages: Vec<ChatMessage>,
    #[schema(required)]
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub seq: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ConversationSummary {
    pub id: Uuid,
    #[schema(required)]
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub summary: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Default)]
pub struct ChatState {
    pub messages: Vec<ChatMessage>,
    pub internal_state: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InternalState {
    pub messages: Vec<Message>,
    pub timestamps: Vec<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq)]
pub struct ChatMessage {
    pub message_type: MessageType,
    pub content: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
}

#[derive(Clone, Eq, PartialEq, Default, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    #[default]
    Human,
    System,
    Ai,
    Tool,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, ToSchema)]
pub struct LLMInfo {
    pub api_base: String,
    pub model: String,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MessageType::System => write!(f, "system"),
            MessageType::Ai => write!(f, "ai"),
            MessageType::Human => write!(f, "human"),
            MessageType::Tool => write!(f, "tool"),
        }
    }
}

impl ChatMessage {
    pub fn human(message: String) -> Self {
        ChatMessage {
            message_type: MessageType::Human,
            content: message,
            timestamp: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AiFlags {
    pub completions: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AiTool {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}
