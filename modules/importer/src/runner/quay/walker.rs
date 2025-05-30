use crate::model::QuayImporter;
use crate::runner::common::Error;
use crate::runner::progress::Progress;
use crate::runner::report::ReportBuilder;
use reqwest::header;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};

const QUAY_API_TOKEN: &str = "QUAY_API_TOKEN";

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LastModified(Option<i64>);

pub struct QuayWalker<P: Progress> {
    continuation: LastModified,
    importer: QuayImporter,
    ingestor: IngestorService,
    report: Arc<Mutex<ReportBuilder>>,
    progress: P,
    client: reqwest::Client,
}

impl<P: Progress> QuayWalker<P> {
    pub fn new(
        importer: QuayImporter,
        ingestor: IngestorService,
        report: Arc<Mutex<ReportBuilder>>,
        progress: P,
    ) -> Result<Self, Error> {
        let client = match std::env::var(QUAY_API_TOKEN) {
            Ok(token) => {
                let token = format!("Bearer {token}");
                let mut auth_value = header::HeaderValue::from_str(&token)?;
                auth_value.set_sensitive(true);
                let mut headers = header::HeaderMap::new();
                headers.insert(header::AUTHORIZATION, auth_value);
                reqwest::Client::builder()
                    .default_headers(headers)
                    .build()?
            }
            _ => {
                log::warn!(
                    "{QUAY_API_TOKEN} environment variable not set; results will be restricted"
                );
                Default::default()
            }
        };

        Ok(Self {
            continuation: LastModified(None),
            importer,
            ingestor,
            report,
            progress,
            client,
        })
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: LastModified) -> Self {
        self.continuation = continuation;
        self
    }

    /// Run the walker
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<LastModified, Error> {
        let repos = self.repositories(Some(String::new())).await?;
        log::debug!("Quay walker found {} repositories", repos.len());

        Ok(LastModified(Some(
            OffsetDateTime::now_utc().unix_timestamp(),
        )))
    }

    async fn repositories(&self, page: Option<String>) -> Result<Vec<Repository>, Error> {
        match page {
            None => Ok(vec![]),
            Some(page) => {
                let mut batch: Batch = self
                    .client
                    .get(self.importer.repositories_url(&page))
                    .send()
                    .await?
                    .json()
                    .await?;
                batch
                    .repositories
                    .append(&mut Box::pin(self.repositories(batch.next_page)).await?);
                Ok(batch.repositories)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct Repository {
    namespace: String,
    name: String,
    last_modified: Option<i64>,
    tags: Option<HashMap<String, Tag>>,
}

#[derive(Debug, Deserialize)]
struct Batch {
    repositories: Vec<Repository>,
    next_page: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Tag {
    name: String,
    size: i64,
    last_modified: OffsetDateTime,
    manifest_digest: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn fetch_repositories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        if option_env!("QUAY_API_TOKEN").is_some() {
            let walker = QuayWalker::new(
                QuayImporter {
                    source: "https://quay.io".into(),
                    namespace: Some("redhat-user-workloads".into()),
                    ..Default::default()
                },
                ctx.ingestor.clone(),
                Arc::new(Mutex::new(ReportBuilder::new())),
                (),
            )?;
            walker.run().await?;
        }

        Ok(())
    }
}
