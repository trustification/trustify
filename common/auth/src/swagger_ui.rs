use crate::devmode::{self, SWAGGER_UI_CLIENT_ID};
use actix_web::dev::HttpServiceFactory;
use openid::{Client, Discovered, Provider, StandardClaims};
use std::sync::Arc;
use url::Url;
use utoipa::openapi::{
    security::{AuthorizationCode, Flow, OAuth2, Scopes, SecurityScheme},
    OpenApi, SecurityRequirement,
};
use utoipa_swagger_ui::{oauth, Config, SwaggerUi};

#[derive(Clone, Debug, Default, clap::Args)]
#[command(
    rename_all_env = "SCREAMING_SNAKE_CASE",
    next_help_heading = "Swagger UI OIDC"
)]
#[group(id = "swagger")]
pub struct SwaggerUiOidcConfig {
    /// The issuer URL used by the Swagger UI, disabled if none.
    #[arg(long, env)]
    pub swagger_ui_oidc_issuer_url: Option<String>,
    /// The client ID use by the swagger UI frontend
    #[arg(long, env, default_value = "frontend")]
    pub swagger_ui_oidc_client_id: String,
}

impl SwaggerUiOidcConfig {
    pub fn devmode() -> Self {
        Self {
            swagger_ui_oidc_issuer_url: Some(devmode::issuer_url()),
            swagger_ui_oidc_client_id: SWAGGER_UI_CLIENT_ID.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct SwaggerUiOidc {
    pub client_id: String,
    pub auth_url: String,
    pub token_url: String,
}

impl SwaggerUiOidc {
    pub async fn new(config: SwaggerUiOidcConfig) -> anyhow::Result<Option<Self>> {
        let issuer_url = match config.swagger_ui_oidc_issuer_url {
            None => return Ok(None),
            Some(issuer_url) => issuer_url,
        };

        let client: Client<Discovered, StandardClaims> = openid::Client::discover(
            config.swagger_ui_oidc_client_id.clone(),
            None,
            None,
            Url::parse(&issuer_url)?,
        )
        .await?;

        Ok(Some(Self {
            token_url: client.provider.token_uri().to_string(),
            auth_url: client.provider.auth_uri().to_string(),
            client_id: client.client_id,
        }))
    }

    pub async fn from_devmode_or_config(
        devmode: bool,
        config: SwaggerUiOidcConfig,
    ) -> anyhow::Result<Option<Self>> {
        let config = match devmode {
            true => SwaggerUiOidcConfig::devmode(),
            false => config,
        };

        Self::new(config).await
    }

    pub fn apply(&self, swagger: SwaggerUi, openapi: &mut OpenApi) -> SwaggerUi {
        if let Some(components) = &mut openapi.components {
            // the swagger UI expects the full "well known" endpoint
            // let url = format!("{}/.well-known/openid-configuration", self.issuer_url);
            //components.add_security_scheme("oidc", SecurityScheme::OpenIdConnect(OpenIdConnect::new(url)));

            // The swagger UI OIDC client still is weird, let's use OAuth2

            components.add_security_scheme(
                "oidc",
                SecurityScheme::OAuth2(OAuth2::new([Flow::AuthorizationCode(
                    AuthorizationCode::new(
                        &self.auth_url,
                        &self.token_url,
                        Scopes::one("oidc", "OpenID Connect"),
                    ),
                )])),
            );
        }

        openapi.security = Some(vec![SecurityRequirement::new::<_, _, String>("oidc", [])]);

        swagger.oauth(
            oauth::Config::new()
                .client_id(&self.client_id)
                .app_name("Trustification")
                .scopes(vec!["openid".to_string()])
                .use_pkce_with_authorization_code_grant(true),
        )
    }
}

/// Create an [`HttpServiceFactory`] for Swagger UI with OIDC authentication
#[cfg(feature = "actix")]
pub fn swagger_ui_with_auth(
    mut openapi: OpenApi,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
) -> impl HttpServiceFactory {
    let config = Config::new(["/openapi.json"])
        .doc_expansion("list")
        .persist_authorization(true)
        .use_base_layout()
        .request_snippets_enabled(true);

    let mut swagger = SwaggerUi::new("/openapi/{_:.*}").config(config);

    if let Some(swagger_ui_oidc) = &swagger_ui_oidc {
        swagger = swagger_ui_oidc.apply(swagger, &mut openapi);
    }

    swagger.url("/openapi.json", openapi)
}
