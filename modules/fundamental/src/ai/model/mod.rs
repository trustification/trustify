use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ChatState {
    pub messages: Vec<ChatMessage>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ChatMessage {
    pub message_type: MessageType,
    pub content: String,
    pub internal_state: Option<String>,
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

impl Default for ChatState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatState {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    pub fn add_human_message(&mut self, message: String) {
        self.messages.push(ChatMessage {
            message_type: MessageType::Human,
            content: message,
            internal_state: None,
        });
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
