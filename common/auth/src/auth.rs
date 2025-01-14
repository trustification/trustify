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
#[group(id = "auth")]
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
        defaults: bool,
    ) -> Result<Option<(AuthenticatorConfig, AuthorizerConfig)>, anyhow::Error> {
        if self.disabled {
            return Ok(None);
        }
        if defaults {
            log::warn!("Running with default auth config");
            return Ok(Some(Default::default()));
        }

        Ok(Some(match self.config {
            Some(config) => {
                let AuthConfig {
                    disabled,
                    authentication,
                    authorization,
                } = serde_yml::from_reader(std::fs::File::open(config)?)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_disabled_no_defaults() {
        let args = AuthConfigArguments {
            disabled: true,
            config: None,
            clients: SingleAuthenticatorClientConfig::default(),
        };

        let result = args.split(false).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn auth_enabled_with_defaults() {
        let args = AuthConfigArguments {
            disabled: false,
            config: None,
            clients: SingleAuthenticatorClientConfig::default(),
        };

        let result = args.split(true).unwrap();
        assert!(result.is_some());
        let auth_client_configs = result.unwrap().0.clients;
        assert!(!auth_client_configs.is_empty());
        let client_config = auth_client_configs.first();
        assert_eq!(client_config.unwrap().client_id, "frontend");
    }
}
