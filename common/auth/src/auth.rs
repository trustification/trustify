//! Both authentication and authorization

use crate::{
    authenticator::config::{AuthenticatorConfig, SingleAuthenticatorClientConfig},
    authorizer::AuthorizerConfig,
};
use std::path::PathBuf;

#[derive(Clone, Debug, Default, clap::Args)]
#[command(
    rename_all_env = "SCREAMING_SNAKE_CASE",
    next_help_heading = "Authentication & authorization"
)]
pub struct AuthConfigArguments {
    /// Flag to disable authentication and authorization, default is on.
    #[arg(
        id = "auth-disabled",
        default_value_t = false,
        long = "auth-disabled",
        env = "AUTH_DISABLED"
    )]
    pub disabled: bool,

    /// Location of the AuthNZ configuration file
    #[arg(
        id = "auth-configuration",
        long = "auth-configuration",
        env = "AUTH_CONFIGURATION",
        conflicts_with = "SingleAuthenticatorClientConfig"
    )]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub clients: SingleAuthenticatorClientConfig,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct AuthConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub disabled: bool,

    pub authentication: AuthenticatorConfig,

    #[serde(default)]
    pub authorization: AuthorizerConfig,
}

pub fn is_default<D: Default + PartialEq>(d: &D) -> bool {
    d == &D::default()
}

impl AuthConfigArguments {
    pub fn split(
        self,
        devmode: bool,
    ) -> Result<Option<(AuthenticatorConfig, AuthorizerConfig)>, anyhow::Error> {
        // disabled overrides devmode
        if self.disabled {
            return Ok(None);
        }

        // check for devmode
        if devmode {
            log::warn!("Running in developer mode");
            return Ok(Some((AuthenticatorConfig::devmode(), Default::default())));
        }

        Ok(Some(match self.config {
            Some(config) => {
                let AuthConfig {
                    disabled,
                    authentication,
                    authorization,
                } = serde_yaml::from_reader(std::fs::File::open(config)?)?;

                if disabled {
                    return Ok(None);
                }

                (authentication, authorization)
            }
            None => {
                let authn = AuthenticatorConfig {
                    clients: self.clients.expand().collect(),
                };

                (authn, Default::default())
            }
        }))
    }
}
