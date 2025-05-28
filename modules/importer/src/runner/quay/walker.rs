use crate::runner::common::Error;
use crate::runner::progress::Progress;
use crate::runner::report::{Phase, ReportBuilder};
use std::io::{Cursor, Read};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::bytes::Buf;
use tracing::instrument;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};
use zip::ZipArchive;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LastModified(Option<String>);

pub struct QuayWalker<P: Progress> {
    continuation: LastModified,
    source: String,
    ingestor: IngestorService,
    report: Arc<Mutex<ReportBuilder>>,
    progress: P,
    client: reqwest::Client,
}

impl<P: Progress> QuayWalker<P> {
    pub fn new(
        source: impl Into<String>,
        ingestor: IngestorService,
        report: Arc<Mutex<ReportBuilder>>,
        progress: P,
    ) -> Self {
        Self {
            continuation: LastModified(None),
            source: source.into(),
            ingestor,
            report,
            progress,
            client: Default::default(),
        }
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: LastModified) -> Self {
        self.continuation = continuation;
        self
    }

    /// Run the walker
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<LastModified, Error> {
        todo!()
    }
}
