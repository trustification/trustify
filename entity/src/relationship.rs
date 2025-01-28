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
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
#[serde(rename_all = "snake_case")]
// When adding a new variant, also add this to the "relationship" table.
pub enum Relationship {
    #[sea_orm(num_value = 0)]
    ContainedBy,
    #[sea_orm(num_value = 1)]
    DependencyOf,
    #[sea_orm(num_value = 2)]
    DevDependencyOf,
    #[sea_orm(num_value = 3)]
    OptionalDependencyOf,
    #[sea_orm(num_value = 4)]
    ProvidedDependencyOf,
    #[sea_orm(num_value = 5)]
    TestDependencyOf,
    #[sea_orm(num_value = 6)]
    RuntimeDependencyOf,
    #[sea_orm(num_value = 7)]
    ExampleOf,
    #[sea_orm(num_value = 8)]
    GeneratedFrom,
    #[sea_orm(num_value = 9)]
    AncestorOf,
    #[sea_orm(num_value = 10)]
    VariantOf,
    #[sea_orm(num_value = 11)]
    BuildToolOf,
    #[sea_orm(num_value = 12)]
    DevToolOf,
    #[sea_orm(num_value = 13)]
    DescribedBy,
    #[sea_orm(num_value = 14)]
    PackageOf,
    #[sea_orm(num_value = 15)]
    Contains,
    #[sea_orm(num_value = 16)]
    Dependency,
    #[sea_orm(num_value = 17)]
    DevDependency,
    #[sea_orm(num_value = 18)]
    OptionalDependency,
    #[sea_orm(num_value = 19)]
    ProvidedDependency,
    #[sea_orm(num_value = 20)]
    TestDependency,
    #[sea_orm(num_value = 21)]
    RuntimeDependency,
    #[sea_orm(num_value = 22)]
    Example,
    #[sea_orm(num_value = 23)]
    Generates,
    #[sea_orm(num_value = 24)]
    Variant,
    #[sea_orm(num_value = 25)]
    BuildTool,
    #[sea_orm(num_value = 26)]
    DevTool,
    #[sea_orm(num_value = 27)]
    Describes,
    #[sea_orm(num_value = 28)]
    Packages,
    #[sea_orm(num_value = 29)]
    Undefined,
}

impl fmt::Display for Relationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
