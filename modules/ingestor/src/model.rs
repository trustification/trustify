use trustify_common::id::Id;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct IngestResult {
    pub id: Id,
    pub document_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}
