use super::*;

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct CweImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    #[serde(default = "default::source")]
    pub source: String,
}

pub const DEFAULT_SOURCE_CWE_CATALOG: &str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";

mod default {
    pub fn source() -> String {
        super::DEFAULT_SOURCE_CWE_CATALOG.into()
    }
}

impl Deref for CweImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for CweImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}
