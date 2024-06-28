use actix_web::web;
use actix_web_static_files::{deps::static_files::Resource, ResourceFiles};
use std::collections::HashMap;
use trustify_ui::{trustify_ui, UI};

pub struct UiResources {
    resources: HashMap<&'static str, Resource>,
}

impl UiResources {
    pub fn new(ui: &UI) -> anyhow::Result<Self> {
        Ok(Self {
            resources: trustify_ui(ui)?,
        })
    }

    pub fn resources(&self) -> HashMap<&'static str, Resource> {
        self.resources
            .iter()
            .map(|(k, v)| {
                // unfortunately, we can't just clone, but we can do it ourselves
                (
                    *k,
                    Resource {
                        data: v.data,
                        modified: v.modified,
                        mime_type: v.mime_type,
                    },
                )
            })
            .collect()
    }
}

pub fn configure(config: &mut web::ServiceConfig, ui: &UiResources) {
    config.service(ResourceFiles::new("/", ui.resources()).resolve_not_found_to(""));
}
