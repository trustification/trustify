use std::sync::Arc;
use huevos_api::system::System;

mod server;

pub struct State {
    system: System,
}

pub type AppState = Arc<State>;