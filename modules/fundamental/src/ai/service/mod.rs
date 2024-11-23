pub mod tools;

use crate::ai::model::{ChatMessage, ChatState, LLMInfo, MessageType};

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
use std::env;
use std::sync::Arc;
use tokio::sync::OnceCell;
use trustify_common::db::{Database, Transactional};

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

    pub async fn completions<TX: AsRef<Transactional>>(
        &self,
        request: &ChatState,
        _tx: TX,
    ) -> Result<ChatState, Error> {
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

        let mut memory = SimpleMemory::new();
        let mut new_user_messages = Vec::new();

        for chat_message in &request.messages {
            match &chat_message.internal_state {
                None => {
                    new_user_messages
                        .push(Message::new_human_message(chat_message.content.clone()));
                }

                Some(internal_state) => {
                    if !new_user_messages.is_empty() {
                        return Err(Error::BadRequest(
                            "message with internal_state found after messages without".to_string(),
                        ));
                    }
                    match STANDARD.decode(internal_state) {
                        Ok(decoded) => {
                            // todo: implement data encryption to avoid client side tampering
                            let m: Message =
                                serde_json::from_slice(decoded.as_slice()).map_err(|_| {
                                    Error::BadRequest("internal_state failed to decode".to_string())
                                })?;
                            memory.add_message(m);
                        }
                        Err(_) => {
                            return Err(Error::BadRequest("invalid internal_state".to_string()))
                        }
                    }
                }
            }
        }

        let mut history = memory.messages();
        for message in &new_user_messages {
            history.push(message.clone());
        }

        let last_message = new_user_messages
            .pop()
            .ok_or(Error::BadRequest("no new user messages".to_string()))?;
        for message in new_user_messages {
            memory.add_message(message);
        }

        let memory: Arc<tokio::sync::Mutex<dyn BaseMemory>> = memory.into();
        let executor = AgentExecutor::from_agent(agent).with_memory(memory.clone());

        let answer = executor
            .invoke(prompt_args! {
                "input" => last_message.content.clone(),
            })
            .await
            .map_err(Error::ChainError)?;
        history.push(Message::new_ai_message(answer.clone()));

        let mut response = ChatState {
            messages: Vec::new(),
        };

        let memory = memory.lock().await;
        for mut message in memory.messages() {
            if message.message_type == langchain_rust::schemas::MessageType::ToolMessage {
                // hide tool results from the user
                message.content = "".to_string();
            }
            let internal_state = match serde_json::to_vec(&message) {
                Ok(serialized) => {
                    // todo: implement data encryption to avoid client side tampering
                    STANDARD.encode(serialized.as_slice())
                }
                Err(e) => return Err(Error::Internal(e.to_string())),
            };
            let ch = ChatMessage {
                content: message.content.clone(),
                message_type: match message.message_type.clone() {
                    langchain_rust::schemas::MessageType::HumanMessage => MessageType::Human,
                    langchain_rust::schemas::MessageType::AIMessage => MessageType::Ai,
                    langchain_rust::schemas::MessageType::SystemMessage => MessageType::System,
                    langchain_rust::schemas::MessageType::ToolMessage => MessageType::Tool,
                },
                internal_state: Some(internal_state),
            };
            response.messages.push(ch);
        }

        Ok(response)
    }
}

#[cfg(test)]
pub mod test;
