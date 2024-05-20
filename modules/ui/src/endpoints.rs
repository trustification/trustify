use crate::ui::ui_resources;
use actix_web::web;
use actix_web_static_files::ResourceFiles;
use trustify_ui::UI;

pub fn configure(config: &mut web::ServiceConfig, ui: &UI) {
    config.service(ResourceFiles::new("/", ui_resources(ui)).resolve_not_found_to(""));
}
