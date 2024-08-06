use crate::log::init_log;
use anyhow::anyhow;
use clap::Parser;
use postgresql_commands::{pg_dump::PgDumpBuilder, CommandBuilder};
use serde_json::Value;
use std::{io::BufReader, path::PathBuf};
use tokio::io::AsyncWriteExt;
use trustify_common::db;
use trustify_module_importer::{
    model::{CommonImporter, CsafImporter, CveImporter, ImporterConfiguration, SbomImporter},
    server::{context::RunContext, ImportRunner},
};
use trustify_module_storage::service::fs::FileSystemBackend;

#[derive(Debug, Parser)]
pub struct GenerateDump {
    /// The name of the output dump file
    #[arg(short, long, default_value = "dump.sql")]
    output: PathBuf,

    /// The name of the input configuration. Uses a default configuration if missing.
    #[arg(short, long)]
    input: Option<PathBuf>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Instructions {
    import: Vec<ImporterConfiguration>,
}

impl GenerateDump {
    fn load_config(&self) -> anyhow::Result<Instructions> {
        match &self.input {
            Some(input) => Ok(serde_yaml::from_reader(BufReader::new(
                std::fs::File::open(input)?,
            ))?),
            None => {
                let import = vec![
                    ImporterConfiguration::Cve(CveImporter {
                        common: default_common("CVEs starting 2024"),
                        source: "https://github.com/CVEProject/cvelistV5".to_string(),
                        years: Default::default(),
                        start_year: Some(2024),
                    }),
                    ImporterConfiguration::Sbom(SbomImporter {
                        common: default_common("All Red Hat SBOMs"),
                        source: "https://access.redhat.com/security/data/sbom/beta/".to_string(),
                        keys: vec!["https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4".parse()?],
                        v3_signatures: true,
                        only_patterns: vec![],
                    }),
                    ImporterConfiguration::Csaf(CsafImporter {
                        common: default_common("Red Hat VEX documents from 2024"),
                        source: "redhat.com".to_string(),
                        v3_signatures: true,
                        only_patterns: vec!["^cve-2024-".into()],
                    })
                ];

                Ok(Instructions { import })
            }
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        init_log()?;

        let (db, postgres) = db::embedded::create().await?;
        let (storage, _tmp) = FileSystemBackend::for_test().await?;

        let importer = ImportRunner {
            db: db.clone(),
            storage: storage.into(),
            working_dir: None,
        };

        // ingest documents

        self.ingest(importer).await?;

        // create dump

        let output = PgDumpBuilder::new()
            .username(&postgres.settings().username)
            .pg_password(&postgres.settings().password)
            .host(&postgres.settings().host)
            .port(postgres.settings().port)
            .dbname(db.name())
            .file(&self.output)
            .build_tokio()
            .output()
            .await?;

        if !output.status.success() {
            log::error!("Failed to run pg_dump:");
            tokio::io::stderr().write_all(&output.stdout).await?;
            tokio::io::stderr().write_all(&output.stderr).await?;
            Err(anyhow!("Failed to run pg_dump"))
        } else {
            log::info!("Dumped to: {}", self.output.display());
            Ok(())
        }
    }

    async fn ingest(&self, runner: ImportRunner) -> anyhow::Result<()> {
        let config = self.load_config()?;

        for run in config.import {
            log::info!(
                "Ingesting: {}",
                run.description.as_deref().unwrap_or("<unnamed>")
            );

            self.ingest_one(&runner, run).await?;
        }

        log::info!("Done ingesting");

        Ok(())
    }

    async fn ingest_one(
        &self,
        runner: &ImportRunner,
        configuration: ImporterConfiguration,
    ) -> anyhow::Result<()> {
        runner
            .run_once(
                Context {
                    name: "run".to_string(),
                },
                configuration,
                None,
                Value::Null,
            )
            .await?;

        Ok(())
    }
}

fn default_common(description: impl Into<String>) -> CommonImporter {
    CommonImporter {
        disabled: false,
        period: Default::default(),
        description: Some(description.into()),
        labels: Default::default(),
    }
}

#[derive(Debug)]
struct Context {
    name: String,
}

impl RunContext for Context {
    fn name(&self) -> &str {
        &self.name
    }

    async fn is_canceled(&self) -> bool {
        // for generating the dump, we don't cancel
        false
    }
}
