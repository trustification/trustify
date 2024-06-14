use trustify_common::id::Id;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct IngestResult {
    pub id: Id,
    pub document_id: String,
}
