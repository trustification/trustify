use crate::purl_status;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "status")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::purl_status::Entity")]
    PackageStatus,
}

impl Related<purl_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageStatus.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(
    Copy,
    Clone,
    Eq,
    Hash,
    Debug,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
)]
#[strum(serialize_all = "snake_case")]
pub enum Status {
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
    Recommended,
}
