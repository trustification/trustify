use crate::server::RunOutput;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    /// Retrieving the document
    Retrieval,
    /// Validating the retrieved document
    Validation,
    /// Upload to storage
    Upload,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    #[serde(with = "time::serde::rfc3339")]
    pub start_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end_date: OffsetDateTime,

    #[serde(default, alias = "numer_of_items")]
    pub number_of_items: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub messages: BTreeMap<Phase, BTreeMap<String, Vec<Message>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Message {
    pub severity: Severity,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct ReportBuilder {
    report: Report,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            report: Report {
                start_date: OffsetDateTime::now_utc(),
                end_date: OffsetDateTime::now_utc(),
                number_of_items: 0,
                messages: Default::default(),
            },
        }
    }

    pub fn tick(&mut self) {
        self.report.number_of_items += 1;
    }

    pub fn add_error(
        &mut self,
        phase: Phase,
        file: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
    ) {
        let file = file.into();
        let message = message.into();

        self.report
            .messages
            .entry(phase)
            .or_default()
            .entry(file)
            .or_default()
            .push(Message { severity, message });
    }

    pub fn build(mut self) -> Report {
        self.report.end_date = OffsetDateTime::now_utc();
        self.report
    }
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReportVisitor<V> {
    pub report: Arc<Mutex<ReportBuilder>>,
    pub next: V,
}

impl<V> ReportVisitor<V> {
    pub fn new(report: Arc<Mutex<ReportBuilder>>, next: V) -> Self {
        Self { report, next }
    }
}

/// Fail a scanner process.
#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    /// A critical error occurred, we don't even have a report.
    #[error(transparent)]
    Critical(#[from] anyhow::Error),
    /// A normal error occurred, we did capture some information in the report.
    #[error("{err}")]
    Normal {
        #[source]
        err: anyhow::Error,
        output: RunOutput,
    },
}

pub trait SplitScannerError {
    /// Split a [`ScannerError`] into a result and an output, unless it was critical.
    fn split(self) -> anyhow::Result<(RunOutput, anyhow::Result<()>)>;
}

impl SplitScannerError for Result<RunOutput, ScannerError> {
    fn split(self) -> anyhow::Result<(RunOutput, anyhow::Result<()>)> {
        match self {
            Ok(output) => Ok((output, Ok(()))),
            Err(ScannerError::Normal { err, output }) => Ok((output, Err(err))),
            Err(ScannerError::Critical(err)) => Err(err),
        }
    }
}
