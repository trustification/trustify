use crate::labels::Labels;
use async_graphql::SimpleObject;
use sea_orm::{entity::prelude::*, sea_query::IntoCondition, Condition, LinkDef};
use time::OffsetDateTime;
use trustify_common::id::{Id, IdError, TryFilterForId};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, SimpleObject)]
#[sea_orm(table_name = "sbom")]
#[graphql(concrete(name = "Sbom", params()))]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    pub node_id: String,

    pub sha256: String,
    pub sha384: Option<String>,
    pub sha512: Option<String>,
    pub document_id: String,

    pub published: Option<OffsetDateTime>,
    pub authors: Vec<String>,

    #[graphql(derived(owned, into = "HashMap<String,String>", with = "Labels::from"))]
    pub labels: Labels,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::sbom_package::Entity")]
    Packages,
    #[sea_orm(has_many = "super::sbom_file::Entity")]
    Files,
    #[sea_orm(has_one = "super::sbom_node::Entity")]
    Node,
    #[sea_orm(has_many = "super::package_relates_to_package::Entity")]
    PackageRelatesToPackages,
    #[sea_orm(has_one = "super::product_version::Entity")]
    ProductVersion,
}

pub struct SbomPurlsLink;

impl Linked for SbomPurlsLink {
    type FromEntity = Entity;
    type ToEntity = super::qualified_purl::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![
            Relation::Packages.def(),
            super::sbom_package::Relation::Purl.def(),
            super::sbom_package_purl_ref::Relation::Purl.def(),
        ]
    }
}

pub struct SbomVersionedPurlsLink;

impl Linked for SbomVersionedPurlsLink {
    type FromEntity = Entity;
    type ToEntity = super::base_purl::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![
            Relation::Packages.def(),
            super::sbom_package::Relation::Purl.def(),
            super::sbom_package_purl_ref::Relation::Purl.def(),
            super::qualified_purl::Relation::VersionedPurl.def(),
        ]
    }
}

pub struct SbomNodeLink;

impl Linked for SbomNodeLink {
    type FromEntity = Entity;
    type ToEntity = super::sbom_node::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![super::sbom_node::Relation::SbomNode.def().rev()]
    }
}

impl Related<super::sbom_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Packages.def()
    }
}

impl Related<super::sbom_file::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Files.def()
    }
}

impl Related<super::sbom_node::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Node.def()
    }
}

impl Related<super::package_relates_to_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageRelatesToPackages.def()
    }
}

impl Related<super::product_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProductVersion.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl TryFilterForId for Entity {
    fn try_filter(id: Id) -> Result<Condition, IdError> {
        Ok(match id {
            Id::Uuid(uuid) => Column::SbomId.eq(uuid).into_condition(),
            Id::Sha256(hash) => Column::Sha256.eq(hash).into_condition(),
            Id::Sha384(hash) => crate::advisory::Column::Sha384.eq(hash).into_condition(),
            Id::Sha512(hash) => crate::advisory::Column::Sha512.eq(hash).into_condition(),
            n => return Err(IdError::UnsupportedAlgorithm(n.prefix().to_string())),
        })
    }
}
