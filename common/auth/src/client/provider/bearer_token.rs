use super::{super::error::Error, Credentials, TokenProvider};
use async_trait::async_trait;
use std::fmt::{Debug, Formatter};

/// A token provider, using an existing bearer token.
///
/// [token providers]: TokenProvider#implementors
#[derive(Clone)]
pub struct BearerTokenProvider {
    pub token: String,
}

impl Debug for BearerTokenProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerTokenProvider")
            .field("token", &"***")
            .finish()
    }
}

#[async_trait]
impl TokenProvider for BearerTokenProvider {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(Some(Credentials::Bearer(self.token.clone())))
    }
}
