use crate::{
    runner::progress::{Progress, ProgressInstance, TracingProgress, TracingProgressInstance},
    service::ImporterService,
};
use std::{
    fmt::Display,
    time::{Duration, Instant},
};

/// [`Progress`] implementation for using the import service.
pub struct ServiceProgress {
    name: String,
    service: ImporterService,
    tracing: TracingProgress,
}

impl ServiceProgress {
    pub fn new(name: String, service: ImporterService) -> Self {
        Self {
            name: name.clone(),
            service,
            tracing: TracingProgress {
                name,
                period: FLUSH_PERIOD,
            },
        }
    }
}

const FLUSH_PERIOD: Duration = Duration::from_secs(15);

impl Progress for ServiceProgress {
    type Instance = ServiceProgressInstance;

    fn start(&self, work: usize) -> Self::Instance {
        ServiceProgressInstance {
            name: self.name.clone(),
            service: self.service.clone(),
            current: 0,
            total: work,
            last_flush: Instant::now() - FLUSH_PERIOD,
            tracing: self.tracing.start(work),
        }
    }

    async fn message(&self, message: impl Display) {
        let message = message.to_string();
        let _ = self
            .service
            .set_progress_message(&self.name, None, &message)
            .await;
        self.tracing.message(message).await;
    }
}

pub struct ServiceProgressInstance {
    name: String,
    service: ImporterService,
    current: usize,
    total: usize,
    last_flush: Instant,
    tracing: TracingProgressInstance,
}

impl ServiceProgressInstance {
    /// flush the state to the database
    async fn flush(&self) {
        let current = self.current.min(self.total);

        tracing::debug!(
            importer = self.name,
            current,
            total = self.total,
            "Updating progress"
        );

        let _ = self
            .service
            .update_progress(&self.name, None, current as u32, self.total as u32)
            .await;
    }
}

impl ProgressInstance for ServiceProgressInstance {
    async fn increment(&mut self, work: usize) {
        self.tracing.increment(work).await;

        self.current += work;
        if self.last_flush.elapsed() > FLUSH_PERIOD {
            self.last_flush = Instant::now();
            self.flush().await;
        }
    }

    async fn finish(mut self) {
        self.current = self.total;
        self.flush().await;

        self.tracing.finish().await;
    }
}
