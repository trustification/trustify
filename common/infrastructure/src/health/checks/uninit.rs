use crate::health::Check;

/// A check which always fails.
///
/// This can be used as a placeholder when a check cannot be registered during startup, but needs
/// to be added later. If the check is initially missing, the health check run might report
/// a success (as no failed checks where present).
pub struct UninitializedCheck;

impl Check for UninitializedCheck {
    type Error = &'static str;

    async fn run(&self) -> Result<(), Self::Error> {
        Err("Check not yet initialized")
    }
}
