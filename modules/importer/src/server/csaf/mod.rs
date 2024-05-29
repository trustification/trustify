mod report;
pub mod storage;

use crate::{
    model::CsafImporter,
    server::{
        common::{filter::Filter, validation},
        csaf::report::CsafReportVisitor,
        report::{Report, ReportBuilder, ReportVisitor, ScannerError},
    },
};
use csaf_walker::{
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileSource, HttpOptions, HttpSource},
    validation::ValidationVisitor,
    walker::Walker,
};
use parking_lot::Mutex;
use std::{sync::Arc, time::SystemTime};
use tracing::instrument;
use trustify_module_ingestor::{graph::Graph, service::IngestorService};
use url::Url;
use walker_common::fetcher::Fetcher;

impl super::Server {
    #[instrument(skip(self), ret)]
    pub async fn run_once_csaf(
        &self,
        importer: CsafImporter,
        last_run: Option<SystemTime>,
    ) -> Result<Report, ScannerError> {
        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let source: DispatchSource = match Url::parse(&importer.source) {
            Ok(url) => HttpSource::new(
                url,
                Fetcher::new(Default::default()).await?,
                HttpOptions::new().since(last_run),
            )
            .into(),
            Err(_) => FileSource::new(&importer.source, None)?.into(),
        };

        // storage (called by validator)

        let ingestor = IngestorService::new(Graph::new(self.db.clone()), self.storage.clone());
        let storage = storage::StorageVisitor {
            ingestor,
            report: report.clone(),
        };

        // wrap storage with report

        let storage = CsafReportVisitor(ReportVisitor::new(report.clone(), storage));

        // validate (called by retriever)

        let options = validation::options(importer.v3_signatures)?;
        let validation = ValidationVisitor::new(storage).with_options(options);

        // retriever (called by filter)

        let visitor = RetrievingVisitor::new(source.clone(), validation);

        // filter

        let filter = Filter::from_config(visitor, importer.only_patterns)?;

        // walker

        // FIXME: track progress
        Walker::new(source)
            .walk(filter)
            .await
            // if the walker fails, we record the outcome as part of the report, but skip any
            // further processing, like storing the marker
            .map_err(|err| ScannerError::Normal {
                err: err.into(),
                report: report.lock().clone().build(),
            })?;

        Ok(match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build())
    }
}
