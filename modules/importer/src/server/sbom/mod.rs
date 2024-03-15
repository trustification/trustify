use crate::model::SbomImporter;
use crate::server::report::{Report, ReportBuilder, ReportVisitor, ScannerError};
use crate::server::sbom::filter::Filter;
use crate::server::sbom::report::SbomReportVisitor;
use parking_lot::Mutex;
use regex::Regex;
use sbom_walker::retrieve::RetrievingVisitor;
use sbom_walker::source::{DispatchSource, FileSource, HttpOptions, HttpSource};
use sbom_walker::validation::ValidationVisitor;
use sbom_walker::walker::Walker;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};
use trustify_graph::graph::Graph;
use url::Url;
use walker_common::{fetcher::Fetcher, validate::ValidationOptions};

mod filter;
pub mod report;
pub mod storage;

impl super::Server {
    pub async fn run_once_sbom(
        &self,
        sbom: SbomImporter,
        last_run: Option<SystemTime>,
    ) -> Result<Report, ScannerError> {
        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let source: DispatchSource = match Url::parse(&sbom.source) {
            Ok(url) => {
                let keys = sbom
                    .keys
                    .into_iter()
                    .map(|key| key.into())
                    .collect::<Vec<_>>();
                HttpSource::new(
                    url,
                    Fetcher::new(Default::default()).await?,
                    HttpOptions::new().since(last_run).keys(keys),
                )
                .into()
            }
            Err(_) => FileSource::new(&sbom.source, None)?.into(),
        };

        // storage (called by validator)

        let storage = storage::StorageVisitor {
            system: Graph::new(self.db.clone()),
            report: report.clone(),
        };

        // wrap storage with report

        let storage = SbomReportVisitor(ReportVisitor::new(report.clone(), storage));

        // validate (called by retriever)

        //  because we still have GPG v3 signatures
        let options = ValidationOptions::new().validation_date(SystemTime::from(
            Date::from_calendar_date(2007, Month::January, 1)
                .map_err(|err| ScannerError::Critical(err.into()))?
                .midnight()
                .assume_offset(UtcOffset::UTC),
        ));

        let validation = ValidationVisitor::new(storage).with_options(options);

        // retriever (called by filter)

        let visitor = RetrievingVisitor::new(source.clone(), validation);

        // filter

        let filter = Filter {
            only_patterns: sbom
                .only_patterns
                .into_iter()
                .map(|r| Regex::from_str(&r))
                .collect::<Result<_, _>>()
                .map_err(|err| ScannerError::Critical(err.into()))?,
            next: visitor,
        };

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
