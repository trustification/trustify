use crate::health::Check;
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct Probe {
    state: Arc<AtomicBool>,
}

pub struct ProbeCheck {
    error: Cow<'static, str>,
    state: Arc<AtomicBool>,
}

impl Probe {
    /// Create a new probe, which initially is [`State::Down`].
    pub fn new(error: impl Into<Cow<'static, str>>) -> (Self, ProbeCheck) {
        let state = Arc::new(AtomicBool::default());
        (
            Self {
                state: state.clone(),
            },
            ProbeCheck {
                error: error.into(),
                state,
            },
        )
    }

    /// Update the state of the probe
    pub fn set(&self, state: bool) {
        self.state.store(state, Ordering::Relaxed);
    }
}

impl Check for ProbeCheck {
    type Error = Cow<'static, str>;

    async fn run(&self) -> Result<(), Self::Error> {
        match self.state.as_ref().load(Ordering::Relaxed) {
            true => Ok(()),
            false => Err(self.error.clone()),
        }
    }
}
