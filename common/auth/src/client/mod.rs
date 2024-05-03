//! Client side token handling (acquire and refresh)

mod error;
mod inject;
mod provider;

pub use error::*;
pub use inject::*;
pub use provider::*;

use chrono::Utc;

/// Check if something expired or expires soon.
pub trait Expires {
    /// Check if the resource expires before the duration elapsed.
    fn expires_before(&self, duration: chrono::Duration) -> bool;
}

impl Expires for openid::TemporalBearerGuard {
    fn expires_before(&self, duration: chrono::Duration) -> bool {
        match self.expires_at() {
            Some(expires) => expires - Utc::now() <= duration,
            None => false,
        }
    }
}
