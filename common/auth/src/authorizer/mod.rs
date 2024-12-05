mod require;
pub use require::*;

use crate::{
    authenticator::{error::AuthorizationError, user::UserInformation},
    Permission,
};

#[derive(
    Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizerConfig {}

#[derive(Default, Debug, Clone)]
pub struct Authorizer {
    config: Option<AuthorizerConfig>,
}

impl Authorizer {
    pub fn new(config: Option<AuthorizerConfig>) -> Self {
        Self { config }
    }

    /// Require a permission from a user.
    ///
    /// If the user passes the check, the function will return `Ok(())`. Otherwise, an error will be
    /// returned.
    pub fn require(
        &self,
        user: &UserInformation,
        permission: Permission,
    ) -> Result<(), AuthorizationError> {
        if self.config.is_none() {
            log::debug!("Authorization disabled, all permissions granted");
            return Ok(());
        }

        // check if the user is authenticated

        let user = match user {
            UserInformation::Authenticated(user) => user,
            UserInformation::Anonymous => return Err(AuthorizationError::Failed),
        };

        user.require_permission(permission)?;

        // we passed
        Ok(())
    }
}
