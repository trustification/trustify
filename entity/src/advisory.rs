use crate::{
    advisory_vulnerability, affected_package_version_range, cvss3, fixed_package_version,
    not_affected_package_version, vulnerability,
};
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "advisory")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub identifier: String,
    pub location: String,
    pub sha256: String,
    pub published: Option<OffsetDateTime>,
    pub modified: Option<OffsetDateTime>,
    pub withdrawn: Option<OffsetDateTime>,
    pub title: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    //#[sea_orm(has_many = "super::advisory_vulnerability::Entity")]
    //AdvisoryVulnerabilities,

    //#[sea_orm(has_many = "super::vulnerability::Entity")]
    //Vulnerability,
    #[sea_orm(has_many = "super::cvss3::Entity")]
    Cvss3,

    #[sea_orm(has_many = "super::fixed_package_version::Entity")]
    FixedPackageVersion,

    #[sea_orm(has_many = "super::affected_package_version_range::Entity")]
    AffectedPackageVersionRange,

    #[sea_orm(has_many = "super::not_affected_package_version::Entity")]
    NotAffectedPackageVersion,
}

/*
impl Related<advisory_vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdvisoryVulnerabilities.def()
    }
}

 */

impl Related<vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        advisory_vulnerability::Relation::Vulnerability.def()
    }

    fn via() -> Option<RelationDef> {
        Some(advisory_vulnerability::Relation::Advisory.def().rev())
    }
}

impl Related<cvss3::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cvss3.def()
    }
}

impl Related<not_affected_package_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::NotAffectedPackageVersion.def()
    }
}

impl Related<fixed_package_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::FixedPackageVersion.def()
    }
}

impl Related<affected_package_version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AffectedPackageVersionRange.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
