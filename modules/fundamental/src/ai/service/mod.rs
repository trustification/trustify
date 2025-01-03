pub mod tools;

use crate::ai::model::{ChatMessage, ChatState, InternalState, LLMInfo, MessageType};

use crate::ai::service::tools::remote::RemoteToolsProvider;
use crate::Error;
use base64::engine::general_purpose::STANDARD;
use base64::engine::Engine as _;

use langchain_rust::chain::options::ChainCallOptions;
use langchain_rust::chain::Chain;
use langchain_rust::language_models::options::CallOptions;
use langchain_rust::schemas::{BaseMemory, Message};
use langchain_rust::tools::OpenAIConfig;
use langchain_rust::{
    agent::{AgentExecutor, OpenAiToolAgentBuilder},
    llm::openai::OpenAI,
    memory::SimpleMemory,
    prompt_args,
    tools::Tool,
};
use sea_orm::{prelude::Uuid, ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use sea_orm::{ActiveModelTrait, ConnectionTrait, Set};

use std::env;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::OnceCell;

use trustify_common::db::limiter::LimiterTrait;

use trustify_common::db::query::{Filtering, Query};
use trustify_common::db::Database;
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_entity::conversation;

pub const PREFIX: &str = include_str!("prefix.txt");

pub struct AiService {
    llm: Option<OpenAI<OpenAIConfig>>,
    llm_info: Option<LLMInfo>,
    remote_tools_providers: Vec<RemoteToolsProvider>,
    pub local_tools: Vec<Arc<dyn Tool>>,
    tools: OnceCell<Vec<Arc<dyn Tool>>>,
}

impl AiService {
    /// Creates a new instance of the AI service.  It can be run against any OpenAI compatible
    /// API endpoint.  The service is disabled if the OPENAI_API_KEY environment variable is not set.
    /// You can configure the following environment variables to run against different OpenAI compatible:
    ///
    /// * OPENAI_API_KEY
    /// * OPENAI_API_BASE (default: https://api.openai.com/v1)
    /// * OPENAI_MODEL (default: gpt-4o)
    ///
    /// ## Running Against OpenAI:
    /// OpenAI tends to provide cutting edge proprietary models, but they are not open source.
    ///
    /// 1. generate an API key at: https://platform.openai.com/settings/profile?tab=api-keys
    /// 2. export the following env variables:
    /// ```bash
    /// export OPENAI_API_KEY=xxxx
    /// ```
    ///
    /// ## Running Against Groq:
    /// On Groq you can use open source models and has a free tier.
    ///
    /// 1. generate an API key at: https://console.groq.com/keys
    /// 2. export the following env variables:
    /// ```bash
    /// export OPENAI_API_KEY=xxxx
    /// export OPENAI_API_BASE=https://api.groq.com/openai/v1
    /// export OPENAI_MODEL=llama3-groq-70b-8192-tool-use-preview
    /// ```
    ///
    /// ## Running Against Ollama:
    /// Ollama lets you run against open source models locally on your machine, but you need
    /// a machine with a powerful GPU.
    ///
    /// 1. install https://ollama.com/
    /// 2. run `ollama pull llama3.1:70b`
    /// 3. export the following env variables:
    /// ```bash
    /// export OPENAI_API_KEY=ollama
    /// export OPENAI_API_BASE=http://localhost:11434/v1
    /// export OPENAI_MODEL=llama3.1:70b
    /// ```
    ///
    pub fn new(db: Database) -> Self {
        let local_tools = tools::new(db.clone());

        let api_key = env::var("OPENAI_API_KEY");
        let api_key = match api_key {
            Ok(api_key) => api_key,
            Err(_) => {
                return Self {
                    llm: None,
                    llm_info: None,
                    remote_tools_providers: Vec::new(),
                    local_tools,
                    tools: OnceCell::new(),
                };
            }
        };

        let api_base =
            env::var("OPENAI_API_BASE").unwrap_or_else(|_| "https://api.openai.com/v1".to_string());
        let model = env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());

        log::info!("LLM API: {}", api_base.clone());
        log::info!("LLM Model: {}", model);

        let llm_config = OpenAIConfig::default()
            .with_api_base(api_base.clone())
            .with_api_key(api_key);

        let llm = OpenAI::default()
            .with_config(llm_config.clone())
            .with_model(model.clone())
            .with_options(CallOptions::default().with_seed(2000));

        let mut remote_tools_providers = vec![];

        if let Ok(remote_tool_urls) = env::var("REMOTE_AI_TOOL_URLS") {
            let mut i = 0;
            remote_tool_urls.split(',').for_each(|url| {
                i += 1;
                let provider_id = format!("r{}_", i);
                remote_tools_providers.push(RemoteToolsProvider::new(
                    provider_id.clone(),
                    url.to_string(),
                ));
            });
        }

        Self {
            llm: Some(llm),
            llm_info: Some(LLMInfo { api_base, model }),
            remote_tools_providers,
            local_tools,
            tools: OnceCell::new(),
        }
    }

    pub fn completions_enabled(&self) -> bool {
        self.llm.is_some()
    }

    pub fn llm_info(&self) -> Option<LLMInfo> {
        self.llm_info.clone()
    }

    async fn fetch_tools(&self) -> Vec<Arc<dyn Tool>> {
        let mut result = vec![];
        for provider in &self.remote_tools_providers {
            match provider.tools().await {
                Ok(tools) => {
                    for tool in tools {
                        result.push(tool.clone());
                    }
                }
                Err(e) => {
                    log::error!("failed to fetch remote tools: {}", e);
                }
            }
        }

        if env::var("AGENT_DISABLE_LOCAL_TOOLS").is_err() {
            for tool in &self.local_tools {
                result.push(tool.clone());
            }
        }

        result
    }

    async fn tools_ref(&self) -> &Vec<Arc<dyn Tool>> {
        // this handles fetching the remote tools only once on the first request...
        // would be better if we could periodically check for tool updates
        // and cache the results for a certain amount of time
        self.tools
            .get_or_init(|| async { self.fetch_tools().await })
            .await
    }

    pub async fn summarize(&self, messages: &[ChatMessage]) -> Result<String, Error> {
        // we could ask an LLM to summarize the conversation, but for now lets use the first message.
        match messages.first() {
            Some(message) => {
                let mut summary = message.content.clone();
                summary.truncate(97);
                if message.content.len() > 97 {
                    summary.push_str("...");
                }
                Ok(summary)
            }
            None => Ok("...".to_string()),
        }
    }
    pub async fn completions(&self, request: &ChatState) -> Result<ChatState, Error> {
        // get the previous LLM message history
        let internal_state = match &request.internal_state {
            Some(internal_state) => match STANDARD.decode(internal_state) {
                Ok(decoded) => {
                    let internal_state: InternalState = serde_json::from_slice(decoded.as_slice())
                        .map_err(|_| {
                            Error::BadRequest("internal_state failed to decode".to_string())
                        })?;
                    internal_state
                }
                Err(_) => return Err(Error::BadRequest("invalid internal_state".to_string())),
            },
            None => InternalState {
                messages: Vec::new(),
                timestamps: Vec::new(),
            },
        };

        let internal_state = self
            .completions_decoded(&request.messages, &internal_state)
            .await?;

        let messages = internal_state.chat_messages();

        // encode the internal state
        let internal_state = match serde_json::to_vec(&internal_state) {
            Ok(serialized) => {
                // todo: implement data encryption to avoid client side tampering
                STANDARD.encode(serialized.as_slice())
            }
            Err(e) => return Err(Error::Internal(e.to_string())),
        };

        Ok(ChatState {
            messages,
            internal_state: Some(internal_state),
        })
    }

    async fn completions_decoded(
        &self,
        request_messages: &Vec<ChatMessage>,
        internal_state: &InternalState,
    ) -> Result<InternalState, Error> {
        let llm = match self.llm.clone() {
            Some(llm) => llm,
            None => return Err(Error::NotFound("AI service is not enabled".to_string())),
        };

        let agent = OpenAiToolAgentBuilder::new()
            .prefix(PREFIX)
            .tools(self.tools_ref().await)
            .options(
                ChainCallOptions::new()
                    .with_max_tokens(1000)
                    .with_temperature(0.0)
                    .with_seed(1000),
            )
            .build(llm)
            .map_err(Error::AgentError)?;

        if internal_state.messages.len() != internal_state.timestamps.len() {
            return Err(Error::BadRequest("invalid internal_state".to_string()));
        }

        // Get all the new user messages
        let mut new_user_messages = Vec::new();
        if internal_state.messages.is_empty() {
            for chat_message in request_messages {
                // all messages should be user messages...
                if chat_message.message_type != MessageType::Human {
                    return Err(Error::BadRequest(
                        "message without internal_state must be a user message".to_string(),
                    ));
                }
                new_user_messages.push(chat_message.clone());
            }
        } else {
            // find the new user messages...
            for chat_message in request_messages.iter().rev() {
                // Add all the messages at the tail that are human.
                if chat_message.message_type != MessageType::Human {
                    break;
                }
                new_user_messages.push(chat_message.clone());
            }
            new_user_messages.reverse();
        }

        // add all messages from the internal state to the memory
        let mut memory = SimpleMemory::new();
        for message in &internal_state.messages {
            memory.add_message(message.clone());
        }

        // add all new user messages except the last one to the memory
        let last_message = new_user_messages
            .pop()
            .ok_or(Error::BadRequest("no new user messages".to_string()))?;

        // timestamp all the user messages...
        let mut timestamps = internal_state.timestamps.clone();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        timestamps.push(now);

        for message in new_user_messages {
            memory.add_message(Message::new_human_message(message.content.clone()));
            timestamps.push(now);
        }

        // use the last user message as the prompt
        let memory: Arc<tokio::sync::Mutex<dyn BaseMemory>> = memory.into();
        let executor = AgentExecutor::from_agent(agent).with_memory(memory.clone());
        _ = executor
            .invoke(prompt_args! {
                "input" => last_message.content.clone(),
            })
            .await
            .map_err(Error::ChainError)?;

        let memory = memory.lock().await;
        let history = memory.messages();

        // add timestamps for all the new messages added by the LLM to the memory.
        let now = OffsetDateTime::now_utc().unix_timestamp();
        for _i in 0..(history.len() - timestamps.len()) {
            timestamps.push(now);
        }

        // convert the memory messages to ChatMessages
        let internal_state = InternalState {
            messages: history,
            timestamps,
        };
        Ok(internal_state)
    }

    pub async fn upsert_conversation<C: ConnectionTrait>(
        &self,
        conversation_id: Uuid,
        user_id: String,
        messages: &Vec<ChatMessage>,
        if_seq: Option<i32>,
        connection: &C,
    ) -> Result<(conversation::Model, Vec<ChatMessage>), Error> {
        let found = self.fetch_conversation(conversation_id, connection).await?;
        let (internal_state, current_seq) = match found {
            Some((conversation, internal_state)) => {
                // verify that the conversation belongs to the user
                if conversation.user_id != user_id {
                    // make this error look like a not found error to avoid leaking
                    // existence of the conversation
                    Err(Error::NotFound("conversation not found".to_string()))?;
                }
                (internal_state, if_seq.unwrap_or(conversation.seq))
            }
            None => {
                // store the new conversation, LLM request will take a while,
                // and we want subsequent concurrent requests to update this record.
                let internal_state = InternalState::default();
                let seq = if_seq.unwrap_or(0);
                let model = conversation::ActiveModel {
                    id: Set(conversation_id),
                    user_id: Set(user_id),
                    state: Set(serde_json::to_value(&internal_state)
                        .map_err(|e| Error::Internal(e.to_string()))?),
                    summary: Set("".to_string()),
                    seq: Set(seq),
                    updated_at: Set(OffsetDateTime::now_utc()),
                };

                // TODO: check for duplicate conversation_id error, and retry as an update
                // to deal with concurrent initial upsert requests.
                log::info!("inserting conversation into db: {}", conversation_id);
                model.insert(connection).await?;
                (internal_state, seq)
            }
        };

        // generate an assistant response
        log::info!(
            "got conversation: {}, seq: {}, if_seq: {:?}",
            conversation_id,
            current_seq,
            if_seq
        );
        let internal_state = self.completions_decoded(messages, &internal_state).await?;

        let response = internal_state.chat_messages();

        // If summarizing the conversation takes a while, maybe we can figure out how to do it
        // in the background and update the record later.
        let summary = self.summarize(&response).await?;

        let model = conversation::ActiveModel {
            id: Set(conversation_id),
            state: Set(serde_json::to_value(&internal_state)
                .map_err(|e| Error::Internal(e.to_string()))?),
            summary: Set(summary),
            seq: Set(current_seq + 1),
            updated_at: Set(OffsetDateTime::now_utc()),
            ..Default::default()
        };

        let mut query = conversation::Entity::update(model);
        if let Some(seq) = if_seq {
            query = query.filter(conversation::Column::Seq.lte(seq))
        }
        let result = query.exec(connection).await?;

        Ok((result, response))
    }

    pub async fn fetch_conversation<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<(conversation::Model, InternalState)>, Error> {
        let select = conversation::Entity::find_by_id(id);
        let found = select.one(connection).await?;
        Ok(match found {
            Some(conversation) => {
                let internal_state = serde_json::from_value(conversation.state.clone())
                    .map_err(|e| Error::Internal(e.to_string()))?;
                Some((conversation, internal_state))
            }
            None => None,
        })
    }

    pub async fn fetch_conversations<C: ConnectionTrait + Sync + Send>(
        &self,
        user_id: String,
        search: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<conversation::Model>, Error> {
        let limiter = conversation::Entity::find()
            .order_by_desc(conversation::Column::UpdatedAt)
            .filtering(search)?
            .filter(conversation::Column::UserId.eq(user_id))
            .limiting(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            total,
            items: limiter.fetch().await?,
        })
    }

    pub async fn delete_conversation<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        let query = conversation::Entity::delete_by_id(id);
        let result = query.exec(connection).await?;
        Ok(result.rows_affected)
    }
}

impl InternalState {
    pub fn chat_messages(&self) -> Vec<ChatMessage> {
        let mut response_messages = Vec::new();
        for (index, message) in self.messages.iter().enumerate() {
            // Skip showing some of the messages to the user.
            match message.message_type {
                langchain_rust::schemas::MessageType::SystemMessage => continue,
                langchain_rust::schemas::MessageType::ToolMessage => continue,
                langchain_rust::schemas::MessageType::HumanMessage => {}
                langchain_rust::schemas::MessageType::AIMessage => {
                    // is it a tools call?
                    if message.tool_calls.is_some() {
                        continue;
                    }
                }
            }

            response_messages.push(ChatMessage {
                content: message.content.clone(),
                message_type: match message.message_type.clone() {
                    langchain_rust::schemas::MessageType::HumanMessage => MessageType::Human,
                    langchain_rust::schemas::MessageType::AIMessage => MessageType::Ai,
                    langchain_rust::schemas::MessageType::SystemMessage => MessageType::System,
                    langchain_rust::schemas::MessageType::ToolMessage => MessageType::Tool,
                },
                timestamp: OffsetDateTime::from_unix_timestamp(self.timestamps[index])
                    .unwrap_or_else(|_| OffsetDateTime::now_utc()),
            });
        }
        response_messages
    }
}

#[cfg(test)]
pub mod test;
