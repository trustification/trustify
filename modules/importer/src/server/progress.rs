use crate::{
    runner::progress::{Progress, ProgressInstance, TracingProgress, TracingProgressInstance},
    service::ImporterService,
};
use std::{
    fmt::Display,
    future::Future,
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

    fn message(&self, message: impl Display) -> impl Future<Output = ()> + Send {
        // Avoid retaining an arbitrary Display argument in the initial future state.
        let message = message.to_string();
        async move {
            let _ = self
                .service
                .set_progress_message(&self.name, None, &message)
                .await;
            self.tracing.message(message).await;
        }
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::runner::test::{NonSendDisplay, assert_send, assert_send_sync, configuration};
    use sea_orm::EntityTrait;
    use std::{cell::Cell, rc::Rc};
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::{ReadWrite, pagination_cache::PaginationCache};
    use trustify_entity::importer;
    use trustify_test_context::TrustifyContext;
    use uuid::Uuid;

    fn service(ctx: &TrustifyContext) -> ImporterService {
        ImporterService::new(ReadWrite::new(ctx.db.clone()), PaginationCache::for_test())
    }

    async fn record(ctx: &TrustifyContext, name: &str) -> anyhow::Result<importer::Model> {
        Ok(importer::Entity::find_by_id(name)
            .one(&ctx.db)
            .await?
            .expect("test importer exists"))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn message_formats_non_send_display_before_returning_send_future(
        ctx: &TrustifyContext,
    ) -> anyhow::Result<()> {
        assert_send_sync::<ServiceProgress>();
        let service = service(ctx);
        let name = format!("progress-test-{}", Uuid::new_v4());
        service.create(name.clone(), configuration()).await?;
        let reporter = ServiceProgress::new(name.clone(), service.clone());
        let formats = Rc::new(Cell::new(0));
        let future = assert_send(reporter.message(NonSendDisplay(formats.clone())));
        assert_eq!(formats.get(), 1, "formatting must precede polling");
        assert_eq!(record(ctx, &name).await?.progress_message, None);
        future.await;
        assert_eq!(formats.get(), 1);
        assert_eq!(
            record(ctx, &name).await?.progress_message.as_deref(),
            Some("formatted progress")
        );
        assert!(service.delete(&name, None).await?);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn tick_flush_cadence_clamps_and_finish_flushes(
        ctx: &TrustifyContext,
    ) -> anyhow::Result<()> {
        let service = service(ctx);
        let name = format!("progress-test-{}", Uuid::new_v4());
        service.create(name.clone(), configuration()).await?;
        let reporter = ServiceProgress::new(name.clone(), service.clone());
        let mut progress = reporter.start(3);
        assert_eq!(record(ctx, &name).await?.progress_current, None);

        assert_send(progress.tick()).await;
        let first = record(ctx, &name).await?;
        assert_eq!(
            (first.progress_current, first.progress_total),
            (Some(1), Some(3))
        );

        // No sleeps: exercise both sides of the private flush deadline directly.
        progress.last_flush = Instant::now();
        assert_send(progress.tick()).await;
        assert_eq!(progress.current, 2);
        assert_eq!(record(ctx, &name).await?.progress_current, Some(1));

        progress.last_flush = Instant::now() - FLUSH_PERIOD - Duration::from_secs(1);
        assert_send(progress.increment(10)).await;
        assert_eq!(progress.current, 12);
        assert_eq!(record(ctx, &name).await?.progress_current, Some(3));
        assert_send(reporter.message("finishing")).await;
        assert_eq!(
            record(ctx, &name).await?.progress_message.as_deref(),
            Some("finishing")
        );
        assert_send(progress.finish()).await;
        let finished = record(ctx, &name).await?;
        assert_eq!(
            (finished.progress_current, finished.progress_total),
            (Some(3), Some(3))
        );
        assert_eq!(finished.progress_message, None);

        // Finish must flush even if the final work was below the next deadline.
        let mut incomplete = reporter.start(3);
        incomplete.last_flush = Instant::now();
        assert_send(incomplete.tick()).await;
        assert_eq!(incomplete.current, 1);
        assert_send(incomplete.finish()).await;
        assert_eq!(record(ctx, &name).await?.progress_current, Some(3));
        assert!(service.delete(&name, None).await?);
        Ok(())
    }
}
