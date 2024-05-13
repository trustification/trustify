use actix_web::web;
use actix_web_static_files::ResourceFiles;
use trustify_ui::{trustify_ui, UI};

pub fn configure(config: &mut web::ServiceConfig, ui: &UI) {
    config.service(ResourceFiles::new("/", trustify_ui(ui)).resolve_not_found_to(""));
}
