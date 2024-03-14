use serde_json::Value;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct ImportConfiguration {
    pub name: String,
    pub configuration: Value,
}
