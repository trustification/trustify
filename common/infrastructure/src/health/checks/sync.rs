use crate::health::Check;

/// A synchronous check
///
/// **NOTE:** This is not intended to run a blocking operation, as it does not spawn the operation,
/// but runs it directly.
pub struct SyncFnCheck<F, E>(pub F)
where
    F: Fn() -> Result<(), E> + Send + Sync,
    E: std::fmt::Display;

impl<F, E> Check for SyncFnCheck<F, E>
where
    F: Fn() -> Result<(), E> + Send + Sync,
    E: std::fmt::Display,
{
    type Error = E;

    async fn run(&self) -> Result<(), Self::Error> {
        (self.0)()
    }
}

pub fn sync<F, E>(f: F) -> SyncFnCheck<F, E>
where
    F: Fn() -> Result<(), E> + Send + Sync,
    E: std::fmt::Display,
{
    SyncFnCheck(f)
}
