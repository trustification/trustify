pub mod checks;

use crate::health::checks::UninitializedCheck;
use futures::{
    future::TryFutureExt,
    stream::{iter, StreamExt},
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

/// All health checks.
#[derive(Default)]
pub struct HealthChecks {
    pub startup: Checks,
    pub liveness: Checks,
    pub readiness: Checks,
}

/// State of a check
#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum State {
    /// Good
    Up,
    /// Bad
    Down,
}

/// Result of a single check.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    /// The name of the check
    pub name: String,
    /// The state
    pub state: State,
    /// Additional data, ensure that no secret get exposed through this
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

/// Collection of check results.
#[derive(Debug)]
pub struct CheckResults {
    pub results: Vec<CheckResult>,
}

impl CheckResults {
    /// Check if all results are [`State::Up`].
    pub fn all_up(&self) -> bool {
        for result in &self.results {
            if result.state != State::Up {
                return false;
            }
        }
        true
    }
}

pub trait Check: Send + Sync {
    type Error: std::fmt::Display;

    /// Run the check. If it returns an error, the check is considered failed/down.
    fn run(&self) -> impl Future<Output = Result<(), Self::Error>>;
}

impl<F, Fut, E> Check for F
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), E>> + Send + Sync,
    E: std::fmt::Display,
{
    type Error = E;

    async fn run(&self) -> Result<(), Self::Error> {
        (self)().await
    }
}

type CheckFn = dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>>>> + Send + Sync;

struct CheckWrapper {
    check: Arc<CheckFn>,
}

impl CheckWrapper {
    async fn run(&self) -> Result<(), String> {
        (self.check.as_ref())().await
    }
}

pub struct LateRegistration {
    name: String,
    checks: Arc<RwLock<HashMap<String, CheckWrapper>>>,
}

impl LateRegistration {
    pub async fn init<C>(self, check: C)
    where
        C: Check + 'static,
    {
        Checks::wrap_and_register(&self.checks, self.name, check).await;
    }
}

/// Checks for a specific health check type.
#[derive(Default)]
pub struct Checks {
    checks: Arc<RwLock<HashMap<String, CheckWrapper>>>,
}

impl Checks {
    async fn wrap_and_register<N, C>(
        checks: &RwLock<HashMap<String, CheckWrapper>>,
        name: N,
        check: C,
    ) where
        N: Into<String>,
        C: Check + 'static,
    {
        let check = Arc::new(check);
        let check = CheckWrapper {
            check: Arc::new(move || {
                let check = check.clone();
                Box::pin(async move { check.run().map_err(|err| err.to_string()).await })
            }),
        };
        checks.write().await.insert(name.into(), check);
    }

    /// Register a new check.
    ///
    /// When using the [`Infrastructure::run`] function, the closure setting up the application
    /// must
    ///
    /// Registering a check with the same name will replace the old check.
    pub async fn register<C>(&self, name: impl Into<String>, check: C)
    where
        C: Check + 'static,
    {
        Self::wrap_and_register(&self.checks, name, check).await;
    }

    /// Unregister a check. If it isn't registered, nothing will happen.
    pub async fn unregister(&self, name: &str) {
        self.checks.write().await.remove(name);
    }

    /// Register a placeholder now, and provide a way to fill in the actual check later.
    ///
    /// Until [`LateRegistration::init`] is called, the check will report [`State::Down`].
    ///
    /// **NOTE**: This doesn't block another call from adding a check with the same name.
    /// If that's the case, a call to [`LateRegistration::init`] will again override this.
    /// **NOTE**: Not calling [`LateRegistration::init`] will keep the placeholder and never succeed.
    pub async fn register_late(&self, name: impl Into<String>) -> LateRegistration {
        let name = name.into();
        self.register(name.clone(), UninitializedCheck).await;
        LateRegistration {
            name,
            checks: self.checks.clone(),
        }
    }

    pub async fn run(&self) -> CheckResults {
        let results = iter(self.checks.read().await.iter())
            .then(|(name, check)| async {
                match check.run().await {
                    Ok(()) => CheckResult {
                        name: name.clone(),
                        state: State::Up,
                        data: Value::Null,
                    },
                    Err(err) => CheckResult {
                        name: name.clone(),
                        state: State::Down,
                        data: json!({
                            "message": err.to_string(),
                        }),
                    },
                }
            })
            .collect()
            .await;

        CheckResults { results }
    }
}
