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
pub struct CsafImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    pub source: String,

    #[serde(default)]
    pub v3_signatures: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_patterns: Vec<String>,
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
