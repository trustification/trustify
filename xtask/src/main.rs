#![allow(clippy::unwrap_used)]

use clap::{Parser, Subcommand};

mod openapi;

#[derive(Debug, Parser)]
pub struct Xtask {
    #[command(subcommand)]
    command: Command,
}

impl Xtask {
    pub fn run(self) -> anyhow::Result<()> {
        match self.command {
            Command::ValidateOpenapi(command) => command.run(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    ValidateOpenapi(openapi::Validate),
}

fn main() -> anyhow::Result<()> {
    Xtask::parse().run()
}
