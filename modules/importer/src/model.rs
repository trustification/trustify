use serde_json::Value;
use trustify_entity::importer::Model;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct ImportConfiguration {
    pub name: String,
    pub configuration: Value,
}

impl From<Model> for ImportConfiguration {
    fn from(
        Model {
            name,
            configuration,
        }: Model,
    ) -> Self {
        Self {
            name,
            configuration,
        }
    }
}
