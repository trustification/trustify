use actix_web::web;
use actix_web_static_files::ResourceFiles;
use trustify_ui::{trustify_ui, UI};

pub fn configure(config: &mut web::ServiceConfig, ui: &UI) {
    config.service(
        ResourceFiles::new(
            "/",
            trustify_ui(
                ui, /*&UI {
                       version: String::from("99.0.0"),
                       auth_required: String::from("false"),
                       oidc_server_url: String::from(
                           "http://localhost:8180/realms/trustify",
                       ),
                       oidc_client_id: String::from("trustify-ui"),
                       oidc_scope: String::from("email"),
                       analytics_enabled: String::from("false"),
                       analytics_write_key: String::from(""),
                   }*/
            ),
        )
        .resolve_not_found_to(""),
    );
}
