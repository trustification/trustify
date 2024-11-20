use crate::devmode::{self, SWAGGER_UI_CLIENT_ID};
use actix_web::dev::HttpServiceFactory;
use openid::{Client, Discovered, Provider, StandardClaims};
use std::sync::Arc;
use trustify_common::tls::ClientConfig;
use url::Url;
use utoipa::openapi::{
    extensions::Extensions,
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
    /// Make the TLS client insecure, disabling all validation (DANGER!).
    #[arg(
        id = "swagger-ui-tls-insecure",
        long,
        env = "SWAGGER_UI_OIDC_TLS_INSECURE",
        default_value_t = false
    )]
    pub tls_insecure: bool,

    /// Additional certificates which will be added as trust anchors.
    #[arg(
        id = "swagger-ui-tls-ca-certificates",
        long,
        env = "SWAGGER_UI_OIDC_TLS_CA_CERTIFICATES"
    )]
    pub ca_certificates: Vec<String>,

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
            tls_insecure: false,
            ca_certificates: vec![],
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
        let SwaggerUiOidcConfig {
            tls_insecure,
            ca_certificates,
            swagger_ui_oidc_issuer_url,
            swagger_ui_oidc_client_id,
        } = config;

        let client = ClientConfig {
            tls_insecure,
            ca_certificates,
        }
        .build_client()?;

        let issuer_url = match swagger_ui_oidc_issuer_url {
            None => return Ok(None),
            Some(issuer_url) => issuer_url,
        };

        let client: Client<Discovered, StandardClaims> = Client::discover_with_client(
            client,
            swagger_ui_oidc_client_id.clone(),
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

    pub fn apply_to_schema(&self, openapi: &mut OpenApi) {
        if let Some(components) = &mut openapi.components {
            // The swagger UI OIDC client still is weird, let's use OAuth2

            let mut oauth2 = OAuth2::new([Flow::AuthorizationCode(AuthorizationCode::new(
                &self.auth_url,
                &self.token_url,
                Scopes::one("openid", "OpenID Connect"),
            ))]);

            oauth2.extensions = Some({
                Extensions::builder()
                    .add("x-client-id", self.client_id.clone())
                    .add("x-default-scopes", "openid")
                    .build()
            });

            components.add_security_scheme("oidc", SecurityScheme::OAuth2(oauth2));
        }

        openapi.security = Some(vec![SecurityRequirement::new::<_, _, String>("oidc", [])]);
    }

    pub fn apply_swaggerui(&self, swagger: SwaggerUi, openapi: &mut OpenApi) -> SwaggerUi {
        self.apply_to_schema(openapi);

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

    let mut swagger = SwaggerUi::new("/swagger-ui/{_:.*}").config(config);

    if let Some(swagger_ui_oidc) = &swagger_ui_oidc {
        swagger = swagger_ui_oidc.apply_swaggerui(swagger, &mut openapi);
    }

    swagger.url("/openapi.json", openapi)
}
