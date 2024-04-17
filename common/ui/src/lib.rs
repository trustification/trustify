use std::fs;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::Value;

static STATIC_DIR: &str = "./static";

#[derive(Serialize, Clone, Default)]
pub struct UI {
    #[serde(rename(serialize = "VERSION"))]
    pub version: String,

    #[serde(rename(serialize = "AUTH_REQUIRED"))]
    pub auth_required: String,

    #[serde(rename(serialize = "OIDC_SERVER_URL"))]
    pub oidc_server_url: String,

    #[serde(rename(serialize = "OIDC_CLIENT_ID"))]
    pub oidc_client_id: String,

    #[serde(rename(serialize = "OIDC_SCOPE"))]
    pub oidc_scope: String,

    #[serde(rename(serialize = "ANALYTICS_ENABLED"))]
    pub analytics_enabled: String,

    #[serde(rename(serialize = "ANALYTICS_WRITE_KEY"))]
    pub analytics_write_key: String,
}

pub fn generate_index_html(ui: &UI) -> tera::Result<String> {
    let template_file = fs::read_to_string(format!("{STATIC_DIR}/{}", "index.html.ejs"))?;
    let template = template_file
        .replace("<%=", "{{")
        .replace("%>", "}}")
        .replace(
            "?? branding.application.title",
            "| default(value=branding.application.title)",
        )
        .replace(
            "?? branding.application.title",
            "| default(value=branding.application.title)",
        );

    let env_json = serde_json::to_string(&ui)?;
    let env_base64 = BASE64_STANDARD.encode(env_json.as_bytes());

    let branding_file_content =
        fs::read_to_string(format!("{STATIC_DIR}/{}", "branding/strings.json"))?;
    let branding: Value = serde_json::from_str(&branding_file_content)?;

    let mut context = tera::Context::new();
    context.insert("_env", &env_base64);
    context.insert("branding", &branding);

    tera::Tera::one_off(&template, &context, true)
}
