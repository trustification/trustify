use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use crate::{advisory_vulnerability, vulnerability};

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
    #[sea_orm(has_many = "super::advisory_vulnerability::Entity")]
    AdvisoryVulnerabilities,

    #[sea_orm(has_many = "super::vulnerability::Entity")]
    Vulnerability
}

impl Related<advisory_vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdvisoryVulnerabilities.def()
    }
}

impl Related<vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        advisory_vulnerability::Relation::Vulnerability.def()
    }

    fn via() -> Option<RelationDef> {
        Some( advisory_vulnerability::Relation::Advisory.def().rev() )
    }
}


/*

impl Related<crate::vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }

    fn via() -> Option<RelationDef> {
        Some(crate::advisory_vulnerability::Relation::Vulnerability.def())
    }
}

 */

impl ActiveModelBehavior for ActiveModel {}
