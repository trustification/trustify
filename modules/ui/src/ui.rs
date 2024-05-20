use std::collections::HashMap;

use static_files::Resource;
use trustify_ui::{trustify_ui, UI};

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

pub fn ui_resources(ui: &UI) -> HashMap<&'static str, Resource> {
    let resources = generate();
    trustify_ui(ui, resources)
}
