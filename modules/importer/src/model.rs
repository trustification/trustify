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
            revision: _,
        }: Model,
    ) -> Self {
        Self {
            name,
            configuration,
        }
    }
}

impl From<Model> for Revisioned<ImportConfiguration> {
    fn from(
        Model {
            name,
            configuration,
            revision,
        }: Model,
    ) -> Self {
        Self {
            value: ImportConfiguration {
                name,
                configuration,
            },
            revision: revision.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct Revisioned<T> {
    pub value: T,
    pub revision: String,
}
