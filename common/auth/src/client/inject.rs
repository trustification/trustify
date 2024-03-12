use super::{error::Error, Credentials, TokenProvider};
use async_trait::async_trait;
use tracing::instrument;

/// Allows injecting tokens.
#[async_trait]
pub trait TokenInjector: Sized + Send + Sync {
    async fn inject_token(self, token_provider: &dyn TokenProvider) -> Result<Self, Error>;
}

/// Injects tokens into a request by setting the authorization header to a "bearer" token.
#[async_trait]
impl TokenInjector for reqwest::RequestBuilder {
    #[instrument(level = "debug", skip(token_provider), err)]
    async fn inject_token(self, token_provider: &dyn TokenProvider) -> Result<Self, Error> {
        if let Some(credentials) = token_provider.provide_access_token().await? {
            Ok(match credentials {
                Credentials::Bearer(token) => self.bearer_auth(token),
                Credentials::Basic(username, password) => self.basic_auth(username, password),
            })
        } else {
            Ok(self)
        }
    }
}
