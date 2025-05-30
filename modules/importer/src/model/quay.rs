use super::*;

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct QuayImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    // To which API paths, e.g. /api/v1/repository, will be appended
    #[serde(default = "default::source")]
    pub source: String,

    // If None, pass public=true
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

pub const DEFAULT_SOURCE_QUAY: &str = "https://quay.io";

mod default {
    pub fn source() -> String {
        super::DEFAULT_SOURCE_QUAY.into()
    }
}

impl Deref for QuayImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for QuayImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

impl QuayImporter {
    pub fn repositories_url(&self, page: &str) -> String {
        let filter = match &self.namespace {
            None => "public=true".to_string(),
            Some(v) => format!("namespace={v}"),
        };
        format!(
            "{}/api/v1/repository?{filter}&last_modified=true&next_page={page}",
            self.source
        )
    }
    pub fn repository_url(&self, namespace: &str, name: &str) -> String {
        format!("{}/api/v1/repository/{namespace}/{name}", self.source)
    }
}
