use super::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OsvImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    /// The URL to the git repository of the OSV data
    pub source: String,

    /// An optional branch. Will use the default branch otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,

    /// An optional path to start searching for documents. Will use the root of the repository otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Deref for OsvImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for OsvImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}
