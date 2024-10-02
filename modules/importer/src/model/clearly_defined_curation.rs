use super::*;
use std::collections::HashSet;

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
pub struct ClearlyDefinedCurationImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    #[serde(default = "default::source")]
    pub source: String,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub types: HashSet<ClearlyDefinedPackageType>,
}

pub const DEFAULT_SOURCE_CLEARLY_DEFINED_CURATION: &str =
    "https://github.com/clearlydefined/curated-data";

mod default {
    pub fn source() -> String {
        super::DEFAULT_SOURCE_CLEARLY_DEFINED_CURATION.into()
    }
}

impl Deref for ClearlyDefinedCurationImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for ClearlyDefinedCurationImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}
