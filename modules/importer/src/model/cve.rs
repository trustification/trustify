use super::*;
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CveImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    #[serde(default = "default::source")]
    pub source: String,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub years: HashSet<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_year: Option<u16>,
}

pub const DEFAULT_SOURCE_CVEPROJECT: &str = "https://github.com/CVEProject/cvelistV5";

mod default {
    pub fn source() -> String {
        super::DEFAULT_SOURCE_CVEPROJECT.into()
    }
}

impl Deref for CveImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for CveImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}
