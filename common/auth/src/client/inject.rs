use super::{error::Error, Credentials, TokenProvider};
use std::future::Future;
use tracing::instrument;

/// Allows injecting tokens.
pub trait TokenInjector: Sized + Send + Sync {
    fn inject_token(
        self,
        token_provider: &dyn TokenProvider,
    ) -> impl Future<Output = Result<Self, Error>> + Send;
}

/// Injects tokens into a request by setting the authorization header to a "bearer" token.
impl TokenInjector for reqwest::RequestBuilder {
    #[instrument(level = "debug", skip(token_provider), err(level=tracing::Level::INFO))]
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
