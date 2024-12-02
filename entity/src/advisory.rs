use crate::{advisory_vulnerability, cvss3, labels::Labels, organization, vulnerability};
use async_graphql::*;
use sea_orm::{entity::prelude::*, sea_query::IntoCondition, Condition};
use std::sync::Arc;
use time::OffsetDateTime;
use trustify_common::{
    db,
    id::{Id, IdError, TryFilterForId},
};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, SimpleObject)]
#[graphql(complex)]
#[graphql(concrete(name = "Advisory", params()))]
#[sea_orm(table_name = "advisory")]
pub struct Model {
    /// The database internal ID
    #[sea_orm(primary_key)]
    pub id: Uuid,
    /// A unique document identifier
    #[graphql(name = "name")]
    pub identifier: String,
    pub version: Option<String>,
    /// An ID as claimed by the document
    pub document_id: String,
    pub deprecated: bool,
    pub issuer_id: Option<Uuid>,
    pub published: Option<OffsetDateTime>,
    pub modified: Option<OffsetDateTime>,
    pub withdrawn: Option<OffsetDateTime>,
    pub title: Option<String>,
    pub labels: Labels,
    pub source_document_id: Option<Uuid>,
}

#[ComplexObject]
impl Model {
    async fn organization<'a>(&self, ctx: &Context<'a>) -> Result<organization::Model> {
        let db = ctx.data::<Arc<db::Database>>()?;
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

    async fn vulnerabilities<'a>(&self, ctx: &Context<'a>) -> Result<Vec<vulnerability::Model>> {
        let db = ctx.data::<Arc<db::Database>>()?;
        Ok(self
            .find_related(vulnerability::Entity)
            .all(&db.connection(&db::Transactional::None))
            .await?)
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::source_document::Entity"
        from = "Column::SourceDocumentId"
        to = "super::source_document::Column::Id")]
    SourceDocument,

    #[sea_orm(
        belongs_to = "super::organization::Entity"
        from = "Column::IssuerId"
        to = "super::organization::Column::Id")]
    Issuer,

    #[sea_orm(has_many = "super::cvss3::Entity")]
    Cvss3,

    #[sea_orm(has_many = "super::advisory_vulnerability::Entity")]
    AdvisoryVulnerability,
}

impl Related<super::source_document::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SourceDocument.def()
    }
}

impl Related<organization::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Issuer.def()
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

impl Related<advisory_vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdvisoryVulnerability.def()
    }
}

impl Related<cvss3::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cvss3.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl TryFilterForId for Entity {
    fn try_filter(id: Id) -> Result<Condition, IdError> {
        Ok(match id {
            Id::Uuid(uuid) => Column::Id.eq(uuid).into_condition(),
            Id::Sha256(hash) => super::source_document::Column::Sha256
                .eq(hash)
                .into_condition(),
            Id::Sha384(hash) => super::source_document::Column::Sha384
                .eq(hash)
                .into_condition(),
            Id::Sha512(hash) => super::source_document::Column::Sha512
                .eq(hash)
                .into_condition(),
            n => return Err(IdError::UnsupportedAlgorithm(n.prefix().to_string())),
        })
    }
}
