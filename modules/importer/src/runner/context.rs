use crate::runner::progress::Progress;
use std::{fmt::Debug, future::Future};
use tokio::runtime::Handle;

/// Shared context for cooperative cancellation and progress of an import run.
pub trait RunContext: Debug + Send + Sync {
    /// Get the name of the import job
    fn name(&self) -> &str;

    /// Check if the run is canceled.
    ///
    /// This is a cooperative way to check if the job needs to be terminated.
    fn is_canceled(&self) -> impl Future<Output = bool> + Send;

    /// A sync version of [`Self::is_canceled`].
    ///
    /// **NOTE:** Requires to be called from a Tokio context.
    fn is_canceled_sync(&self) -> bool {
        Handle::current().block_on(async { self.is_canceled().await })
    }

    fn check_canceled_sync<E, F>(&self, f: F) -> Result<(), E>
    where
        F: FnOnce() -> E,
    {
        match self.is_canceled_sync() {
            true => Err(f()),
            false => Ok(()),
        }
    }

    fn check_canceled<E, F>(&self, f: F) -> impl Future<Output = Result<(), E>> + Send
    where
        F: FnOnce() -> E + Send,
    {
        async {
            match self.is_canceled().await {
                true => Err(f()),
                false => Ok(()),
            }
        }
    }

    fn progress(&self, #[allow(unused)] message: String) -> impl Progress + 'static {}
}

// Handy for testing
impl RunContext for () {
    fn name(&self) -> &str {
        ""
    }
    async fn is_canceled(&self) -> bool {
        false
    }
    fn progress(&self, _message: String) -> impl Progress + 'static {}
}

#[cfg(test)]
mod test {
    use super::RunContext;
    use crate::runner::test::{TestRunContext, assert_send, assert_send_sync};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test_log::test(tokio::test)]
    async fn cancellation_factory_is_only_called_when_canceled() {
        assert_send_sync::<TestRunContext>();
        let context = TestRunContext::default();
        let calls = AtomicUsize::new(0);
        let error = || {
            calls.fetch_add(1, Ordering::SeqCst);
            "canceled"
        };

        assert!(!assert_send(context.is_canceled()).await);
        assert_eq!(assert_send(context.check_canceled(error)).await, Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        context.canceled.store(true, Ordering::SeqCst);
        assert!(assert_send(context.is_canceled()).await);
        assert_eq!(
            assert_send(context.check_canceled(error)).await,
            Err("canceled")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(assert_send(().check_canceled(error)).await, Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
