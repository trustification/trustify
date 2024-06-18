use actix_web::web;
use actix_web_static_files::ResourceFiles;
use trustify_ui::{trustify_ui, UI};

pub fn configure(config: &mut web::ServiceConfig, ui: &UI) {
    config.service(ResourceFiles::new("/", trustify_ui(ui)).resolve_not_found_to(""));
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_web::{test, App};

    #[test]
    async fn test_ui_get() {
        let test_ui = UI {
            version: "".to_string(),
            auth_required: "".to_string(),
            oidc_server_url: "".to_string(),
            oidc_client_id: "".to_string(),
            oidc_scope: "".to_string(),
            analytics_enabled: "".to_string(),
            analytics_write_key: "".to_string(),
        };

        let app = test::init_service(App::new().configure(|cfg| configure(cfg, &test_ui))).await;

        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body = test::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("Trustification"));
        assert!(body_str.contains("You need to enable JavaScript to run this app"));
    }
}
