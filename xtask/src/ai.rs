use anyhow::anyhow;
use clap::Parser;
use nu_ansi_term::Color::Blue;
use reedline::FileBackedHistory;
use reedline::{DefaultPrompt, DefaultPromptSegment, Reedline, Signal};
use trustify_module_fundamental::ai::model::{ChatState, MessageType};

#[derive(Debug, Parser, Default)]
pub struct Ai {
    /// trustd api endpoint
    #[arg(long, default_value = "http://localhost:8080")]
    url: String,
}

impl Ai {
    pub async fn run(self) -> anyhow::Result<()> {
        run(self.url).await
    }
}

async fn run(url: String) -> anyhow::Result<()> {
    let history = Box::new(FileBackedHistory::with_file(500, ".ai_history.txt".into())?);
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

    println!("Using Trustify endpoint: {}", url);

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

                let client = reqwest::Client::new();
                let res = client
                    .post(format!("{}/api/v1/ai/completions", url))
                    .json(&chat_state)
                    .send()
                    .await?;

                if res.status() != 200 {
                    println!("Error: {}, {}", res.status(), res.text().await?);
                    continue;
                }

                let new_state: ChatState =
                    res.json().await.map_err(|x| anyhow!("failed {:?}", x))?;

                // Uncomment to print all messages in the chat history:
                // for message in &new_state.messages {
                //     println!(
                //         "      {}: {}",
                //         LightGray.paint(message.message_type.to_string()),
                //         DarkGray.paint(message.content.clone())
                //     );
                // }

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
