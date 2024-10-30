use crate::openapi::Openapi;
use crate::schema::GenerateSchema;
use anyhow::anyhow;
use clap::Parser;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Parser)]
pub struct Precommit {}

impl Precommit {
    pub async fn run(self) -> anyhow::Result<()> {
        GenerateSchema {
            base: Path::new(".").to_path_buf(),
        }
        .run()
        .await?;

        Openapi::default().run().await?;

        println!("Running: cargo clippy");
        if !Command::new("cargo")
            .args([
                "clippy",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
                "-D",
                "clippy::unwrap_used",
                "-D",
                "clippy::expect_used",
            ])
            .status()
            .map_err(|_| anyhow!("cargo clippy failed"))?
            .success()
        {
            return Err(anyhow!("cargo clippy failed"));
        }

        println!("Running: cargo fmt");
        if !Command::new("cargo")
            .args(["fmt"])
            .status()
            .map_err(|_| anyhow!("cargo fmt failed"))?
            .success()
        {
            return Err(anyhow!("cargo fmt failed"));
        }

        println!("Running: cargo check");
        if !Command::new("cargo")
            .args(["check"])
            .status()
            .map_err(|_| anyhow!("cargo check failed"))?
            .success()
        {
            return Err(anyhow!("cargo check failed"));
        }
        Ok(())
    }
}
