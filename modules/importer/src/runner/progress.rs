use std::{
    fmt::Display,
    future::{Future, ready},
    time::{Duration, Instant},
};
use tokio::runtime::Handle;

/// Shareable progress reporter with Send update futures.
pub trait Progress: Send + Sync {
    type Instance: ProgressInstance;

    /// start a new work package
    fn start(&self, work: usize) -> Self::Instance;

    /// Format a message before constructing its Send future; updates remain deferred.
    /// Formatting also occurs when the returned future is never polled.
    fn message(&self, message: impl Display) -> impl Future<Output = ()> + Send;

    fn message_sync(&self, message: impl Display) {
        Handle::current().block_on(async { self.message(message).await })
    }
}

impl Progress for () {
    type Instance = ();

    fn start(&self, _work: usize) -> Self::Instance {}

    fn message(&self, _message: impl Display) -> impl Future<Output = ()> + Send {
        ready(())
    }
}

impl ProgressInstance for () {
    async fn increment(&mut self, _work: usize) {}

    async fn finish(self) {}
}

/// Owned work-package progress; mutable updates need Send, not Sync.
pub trait ProgressInstance: Sized + Send {
    fn tick(&mut self) -> impl Future<Output = ()> + Send {
        self.increment(1)
    }

    /// Sync version of [`tick`].
    ///
    /// **NOTE:** Requires to be called from a tokio context
    fn tick_sync(&mut self) {
        Handle::current().block_on(async { self.tick().await })
    }

    fn increment(&mut self, work: usize) -> impl Future<Output = ()> + Send;

    fn finish(self) -> impl Future<Output = ()> + Send;

    fn finish_sync(self) {
        Handle::current().block_on(async { self.finish().await })
    }
}

/// Report progress to tracing, with a rate limit.
#[derive(Clone, Debug)]
pub struct TracingProgress {
    pub name: String,
    pub period: Duration,
}

pub struct TracingProgressInstance {
    name: String,

    total: usize,
    current: usize,

    start: Instant,
    period: Duration,
    last: Instant,
}

impl Progress for TracingProgress {
    type Instance = TracingProgressInstance;

    fn start(&self, work: usize) -> Self::Instance {
        tracing::info!("Starting: {} - total: {work}", self.name);

        TracingProgressInstance {
            name: self.name.clone(),
            total: work,
            current: 0,
            start: Instant::now(),
            period: self.period,
            // first report with update
            last: Instant::now() - self.period,
        }
    }

    fn message(&self, message: impl Display) -> impl Future<Output = ()> + Send {
        // Format before constructing the future so a non-Send Display is not retained.
        let message = message.to_string();
        async move {
            tracing::info!("Progress: {message}");
        }
    }
}

impl ProgressInstance for TracingProgressInstance {
    async fn increment(&mut self, work: usize) {
        self.current += work;
        self.current = self.current.min(self.total);

        if self.last.elapsed() >= self.period {
            self.last = Instant::now();

            let p = self.current as f64 / self.total as f64;
            tracing::info!(
                current = self.current,
                total = self.total,
                percent = p * 100.0,
                "{}: {:.2}% (ETA: {})",
                self.name,
                p * 100.0,
                self.eta()
                    // truncate to seconds
                    .map(|eta| Duration::from_secs(eta.as_secs()))
                    // nice format
                    .map(humantime::Duration::from)
                    // to string ...
                    .map(|eta| eta.to_string())
                    // ... so that we can provide a nice default
                    .unwrap_or_else(|| "?".to_string())
            );
        }
    }

    async fn finish(self) {
        tracing::info!(percent = 100f64, "{}: 100% (complete)", self.name);
    }
}

impl TracingProgressInstance {
    fn eta(&self) -> Option<Duration> {
        if self.current == 0 {
            return None;
        }

        let per_item = self.current as f64 / self.start.elapsed().as_secs_f64();
        let remaining = self.total - self.current;
        let remaining = remaining as f64 / per_item;

        Some(Duration::from_secs_f64(remaining))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::runner::test::{NonSendDisplay, assert_send, assert_send_sync};
    use parking_lot::Mutex;
    use std::{cell::Cell, rc::Rc, sync::Arc};

    #[derive(Clone, Default)]
    struct MockProgress {
        updates: Arc<Mutex<Vec<usize>>>,
    }

    struct MockProgressInstance {
        reporter: Arc<Mutex<Vec<usize>>>,
        total: usize,
        current: usize,
    }

    impl MockProgressInstance {
        fn update(&self, progress: f64) {
            self.reporter.lock().push((progress * 100.0) as _);
        }
    }

    impl Progress for MockProgress {
        type Instance = MockProgressInstance;

        fn start(&self, work: usize) -> Self::Instance {
            MockProgressInstance {
                reporter: self.updates.clone(),
                total: work,
                current: 0,
            }
        }

        fn message(&self, _message: impl Display) -> impl Future<Output = ()> + Send {
            ready(())
        }
    }

    impl ProgressInstance for MockProgressInstance {
        async fn increment(&mut self, work: usize) {
            self.current += work;
            self.current = self.current.min(self.total);

            self.update(self.current as f64 / self.total as f64)
        }

        async fn finish(self) {}
    }

    #[test_log::test(tokio::test)]
    async fn owned_progress_instance_needs_send_not_sync() {
        struct LocalCounter(Cell<usize>);

        impl ProgressInstance for LocalCounter {
            async fn increment(&mut self, work: usize) {
                self.0.set(self.0.get() + work);
            }

            async fn finish(self) {}
        }

        // Cell is Send but not Sync. Mutable ownership is sufficient for the future.
        let mut progress = LocalCounter(Cell::new(0));
        assert_send(progress.tick()).await;
        assert_eq!(progress.0.get(), 1);
        assert_send(progress.finish()).await;
    }

    #[test_log::test(tokio::test)]
    async fn tracing_progress_futures_tick_clamp_and_finish() {
        assert_send_sync::<TracingProgress>();
        let reporter = TracingProgress {
            name: "test".into(),
            period: Duration::ZERO,
        };
        let mut progress = reporter.start(2);
        assert_eq!(progress.current, 0);
        assert_eq!(progress.eta(), None);

        assert_send(progress.tick()).await;
        assert_eq!(progress.current, 1);
        assert_send(progress.increment(10)).await;
        assert_eq!(progress.current, 2);
        assert_eq!(progress.eta(), Some(Duration::ZERO));
        assert_send(progress.finish()).await;

        let mut empty = reporter.start(0);
        assert_send(empty.tick()).await;
        assert_eq!(empty.current, 0);
        assert_send(empty.finish()).await;
    }

    #[test_log::test(tokio::test)]
    async fn tracing_message_formats_non_send_display_before_returning_send_future() {
        let reporter = TracingProgress {
            name: "test".into(),
            period: Duration::ZERO,
        };
        let formats = Rc::new(Cell::new(0));
        let future = assert_send(reporter.message(NonSendDisplay(formats.clone())));
        assert_eq!(formats.get(), 1, "formatting must precede polling");
        future.await;
        assert_eq!(formats.get(), 1);
    }

    #[test_log::test(tokio::test)]
    async fn simple() {
        let reporter = MockProgress::default();
        let mut progress = reporter.start(20);

        for _ in 0..10 {
            progress.tick().await;
        }

        progress.finish().await;

        let updates = reporter.updates.lock().clone();

        assert_eq!(updates, vec![5, 10, 15, 20, 25, 30, 35, 40, 45, 50]);
    }
}
