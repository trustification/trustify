use crate::version_range;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_status")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status_id: Uuid,
    pub package_id: Uuid,
    pub version_range_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::version_range::Entity"
        from = "Column::VersionRangeId",
        to = "super::version_range::Column::Id"
    )]
    VersionRange,

    #[sea_orm(belongs_to = "super::base_purl::Entity",
        from = "Column::PackageId"
        to = "super::base_purl::Column::Id"
    )]
    Package,

    #[sea_orm(belongs_to = "super::vulnerability::Entity",
        from = "Column::VulnerabilityId"
        to = "super::vulnerability::Column::Id"
    )]
    Vulnerability,

    #[sea_orm(belongs_to = "super::advisory::Entity",
        from = "Column::AdvisoryId"
        to = "super::advisory::Column::Id"
    )]
    Advisory,

    #[sea_orm(belongs_to = "super::status::Entity",
        from = "Column::StatusId"
        to = "super::status::Column::Id"
    )]
    Status,

    #[sea_orm(has_many = "super::versioned_purl::Entity")]
    PackageVersion,
}

impl Related<version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionRange.def()
    }
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl Related<super::versioned_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageVersion.def()
    }
}

impl Related<super::vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }
}

impl Related<super::advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl Related<super::status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Status.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
