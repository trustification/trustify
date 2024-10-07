use anyhow::anyhow;
use clap::Parser;
use postgresql_commands::{pg_dump::PgDumpBuilder, CommandBuilder};
use serde_json::Value;
use std::{io::BufReader, path::PathBuf, time::Duration};
use tokio::io::AsyncWriteExt;
use trustify_common::{db, model::BinaryByteSize};
use trustify_module_importer::{
    model::{CommonImporter, CsafImporter, CveImporter, ImporterConfiguration, SbomImporter},
    runner::{
        context::RunContext,
        progress::{Progress, TracingProgress},
        ImportRunner,
    },
};
use trustify_module_storage::service::fs::FileSystemBackend;
use trustify_module_storage::service::Compression;

#[derive(Debug, Parser)]
pub struct GenerateDump {
    /// The name of the output dump file
    #[arg(short, long, default_value = "dump.sql")]
    output: PathBuf,

    /// The name of the input configuration. Uses a default configuration if missing.
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// An optional specified working directory
    #[arg(short, long)]
    working_dir: Option<PathBuf>,

    /// Files greater than this limit will be ignored.
    #[arg(long)]
    size_limit: Option<BinaryByteSize>,

    /// Number of times to retry fetching a document.
    #[arg(long, conflicts_with = "input")]
    fetch_retries: Option<usize>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct Instructions {
    import: Vec<ImporterConfiguration>,
}

impl GenerateDump {
    fn load_config(&self) -> anyhow::Result<Instructions> {
        match &self.input {
            Some(input) => Ok(serde_yml::from_reader(BufReader::new(
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
                        size_limit: self.size_limit,
                        fetch_retries: self.fetch_retries,
                    }),
                    ImporterConfiguration::Csaf(CsafImporter {
                        common: default_common("Red Hat VEX documents from 2024"),
                        source: "redhat.com".to_string(),
                        v3_signatures: true,
                        only_patterns: vec!["^cve-2024-".into()],
                        fetch_retries: self.fetch_retries,
                    })
                ];

                Ok(Instructions { import })
            }
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let (db, postgres) = match &self.working_dir {
            Some(wd) => db::embedded::create_in(wd.join("db")).await?,
            None => db::embedded::create().await?,
        };

        let (storage, _tmp) = match &self.working_dir {
            Some(wd) => (
                FileSystemBackend::new(wd.join("storage"), Compression::Zstd).await?,
                None,
            ),
            None => {
                let (storage, tmp) = FileSystemBackend::for_test().await?;
                (storage, Some(tmp))
            }
        };

        let importer = ImportRunner {
            db: db.clone(),
            storage: storage.into(),
            working_dir: self.working_dir.as_ref().map(|wd| wd.join("wd")),
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

    fn progress(&self, message: String) -> impl Progress + Send + 'static {
        TracingProgress {
            name: format!("{}: {message}", self.name),
            period: Duration::from_secs(15),
        }
    }
}
