use super::*;
use trustify_common::serde::is_default;

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
pub struct CsafImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    pub source: String,

    #[serde(default)]
    pub v3_signatures: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_patterns: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_retries: Option<usize>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub ignore_missing: bool,
}

impl Deref for CsafImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for CsafImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}
