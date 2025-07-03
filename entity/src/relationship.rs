use deepsize::DeepSizeOf;
use sea_orm::{DeriveActiveEnum, EnumIter};
use std::fmt;

#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    strum::VariantArray,
    strum::EnumString,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[derive(DeepSizeOf)]
// When adding a new variant, also add this to the "relationship" table.
pub enum Relationship {
    #[sea_orm(num_value = 0)]
    Contains,
    #[sea_orm(num_value = 1)]
    Dependency,
    #[sea_orm(num_value = 2)]
    DevDependency,
    #[sea_orm(num_value = 3)]
    OptionalDependency,
    #[sea_orm(num_value = 4)]
    ProvidedDependency,
    #[sea_orm(num_value = 5)]
    TestDependency,
    #[sea_orm(num_value = 6)]
    RuntimeDependency,
    #[sea_orm(num_value = 7)]
    Example,
    #[sea_orm(num_value = 8)]
    Generates,
    #[sea_orm(num_value = 9)]
    AncestorOf,
    #[sea_orm(num_value = 10)]
    Variant,
    #[sea_orm(num_value = 11)]
    BuildTool,
    #[sea_orm(num_value = 12)]
    DevTool,
    #[sea_orm(num_value = 13)]
    Describes,
    #[sea_orm(num_value = 14)]
    Package,
    #[sea_orm(num_value = 15)]
    Undefined,
}

impl fmt::Display for Relationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
