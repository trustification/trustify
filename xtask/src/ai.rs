use clap::Parser;
use nu_ansi_term::Color::{Blue, DarkGray, Green, LightGray};
use reedline::FileBackedHistory;
use reedline::{DefaultPrompt, DefaultPromptSegment, Reedline, Signal};
use std::env;
use test_context::AsyncTestContext;
use trustify_module_fundamental::ai::model::{ChatState, MessageType};
use trustify_module_fundamental::ai::service::AiService;
use trustify_test_context::TrustifyContext;

#[derive(Debug, Parser, Default)]
pub struct Ai {}

impl Ai {
    pub async fn run(self) -> anyhow::Result<()> {
        run().await
    }
}

async fn run() -> anyhow::Result<()> {
    // Set the following environment variables to against a different OpenAI API endpoint
    // OPENAI_API_BASE, OPENAI_API_KEY, OPENAI_MODEL

    // export EXTERNAL_TEST_DB to use an external database, otherwise
    // a temporary database will be created for testing.
    let ctx = TrustifyContext::setup().await;

    // if we are not using an external database, ingest some documents so that
    // we use the data in them to respond to questions.
    if env::var("EXTERNAL_TEST_DB").is_err() {
        println!("{}", LightGray.paint("ingesting documents..."));
        ctx.ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
            .await?;
        ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;
        ctx.ingest_document("zookeeper-3.9.2-cyclonedx.json")
            .await?;
        ctx.ingest_document("cve/CVE-2021-32714.json").await?;
        ctx.ingest_document("cve/CVE-2024-26308.json").await?;
        ctx.ingest_document("cve/CVE-2024-29025.json").await?;
        ctx.ingest_document("csaf/cve-2023-33201.json").await?;
        println!("{}", Green.paint("DONE!"));
    }

    let service = AiService::new(ctx.db.clone());
    let llm_info = match service.llm_info() {
        None => {
            println!("{}", LightGray.paint("AI service is not enabled, please set the OPENAI_API_KEY, OPENAI_API_BASE, OPENAI_MODEL env vars."));
            return Ok(());
        }
        Some(llm_info) => llm_info,
    };

    let history = Box::new(FileBackedHistory::with_file(5, ".ai_history.txt".into())?);

    let mut line_editor = Reedline::create().with_history(history);

    let prompt = DefaultPrompt {
        left_prompt: DefaultPromptSegment::Basic("Trustify Assistant".to_string()),
        right_prompt: DefaultPromptSegment::Basic(">>".to_string()),
    };

    println!(
        "{}",
        Blue.paint(
            r#"

Enter your question or type:
    'quit' or 'exit' to exit.
    'clear' to clear chat history.

"#
        )
    );

    println!(
        "Using Model: {}, at endpoint: {}",
        llm_info.model, llm_info.api_base
    );

    let mut chat_state = ChatState::new();
    loop {
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(buffer)) => {
                match buffer.trim().to_lowercase().as_str() {
                    "quit" | "exit" => {
                        println!("{}", Blue.paint("\nBye!"));
                        return Ok(());
                    }
                    "clear" => {
                        chat_state = ChatState::new();
                        println!("{}", Blue.paint("\nChat history cleared..."));
                        continue;
                    }
                    _ => {}
                }

                chat_state.add_human_message(buffer.clone());
                let pos = chat_state.messages.len();

                let new_state = service.completions(&chat_state, ()).await?;

                for message in &new_state.messages {
                    println!(
                        "      {}: {}",
                        LightGray.paint(message.message_type.to_string()),
                        DarkGray.paint(message.content.clone())
                    );
                }

                for i in pos..new_state.messages.len() {
                    let message = &new_state.messages[i];
                    if message.message_type == MessageType::Ai {
                        println!("{}", Blue.paint(&message.content));
                    }
                }

                chat_state = new_state;
            }
            Ok(Signal::CtrlD) | Ok(Signal::CtrlC) => {
                println!("\nBye!");
                break;
            }
            _ => {}
        }
    }
    Ok(())
}
