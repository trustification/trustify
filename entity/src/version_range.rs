use crate::package_status;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "version_range")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    // The ID of the version scheme, which is a human-friend string key like `semver`.
    pub version_scheme_id: String,
    pub low_version: Option<String>,
    pub low_inclusive: Option<bool>,
    pub high_version: Option<String>,
    pub high_inclusive: Option<bool>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::package_status::Entity",
        from = "super::version_range::Column::Id",
        to = "super::package_status::Column::VersionRangeId"
    )]
    PackageStatus,

    #[sea_orm(has_many = "super::package_version::Entity")]
    PackageVersion,
}

impl Related<package_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageStatus.def()
    }
}

impl Related<super::package_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageStatus.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
