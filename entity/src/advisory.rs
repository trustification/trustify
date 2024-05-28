use crate::{
    advisory_vulnerability, affected_package_version_range, cvss3, fixed_package_version,
    not_affected_package_version, organization, vulnerability,
};
use async_graphql::*;
use sea_orm::entity::prelude::*;
use std::sync::Arc;
use time::OffsetDateTime;
use trustify_common::db;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, SimpleObject)]
#[graphql(complex)]
#[graphql(concrete(name = "Advisory", params()))]
#[sea_orm(table_name = "advisory")]

pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub identifier: String,
    pub organization_id: Option<i32>,
    pub location: String,
    pub sha256: String,
    pub published: Option<OffsetDateTime>,
    pub modified: Option<OffsetDateTime>,
    pub withdrawn: Option<OffsetDateTime>,
    pub title: Option<String>,
}

#[ComplexObject]
impl Model {
    async fn organization(&self, ctx: &Context<'_>) -> Result<organization::Model> {
        let db: &Arc<db::Database> = ctx.data::<Arc<db::Database>>()?;
        if let Some(found) = self
            .find_related(organization::Entity)
            .one(&db.connection(&db::Transactional::None))
            .await?
        {
            Ok(found)
        } else {
            Err(Error::new("Organization not found"))
        }
    }

    async fn vulnerabilities(&self, ctx: &Context<'_>) -> Result<Vec<vulnerability::Model>> {
        let db: &Arc<db::Database> = ctx.data::<Arc<db::Database>>()?;
        Ok(self
            .find_related(vulnerability::Entity)
            .all(&db.connection(&db::Transactional::None))
            .await?)
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organization::Entity"
        from = "Column::OrganizationId"
        to = "super::organization::Column::Id")]
    Organization,

    #[sea_orm(has_many = "super::cvss3::Entity")]
    Cvss3,

    #[sea_orm(has_many = "super::fixed_package_version::Entity")]
    FixedPackageVersion,

    #[sea_orm(has_many = "super::affected_package_version_range::Entity")]
    AffectedPackageVersionRange,

    #[sea_orm(has_many = "super::not_affected_package_version::Entity")]
    NotAffectedPackageVersion,
}

impl Related<organization::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organization.def()
    }
}

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
