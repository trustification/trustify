pub mod details;

use super::service::SbomService;
use crate::{
    purl::model::summary::purl::PurlSummary, source_document::model::SourceDocument, Error,
};
use async_graphql::SimpleObject;
use sea_orm::{prelude::Uuid, ModelTrait, PaginatorTrait};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::{db::ConnectionOrTransaction, model::Paginated};
use trustify_entity::{
    labels::Labels, relationship::Relationship, sbom, sbom_node, sbom_package, source_document,
};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomHead {
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub id: Uuid,

    pub document_id: String,
    pub labels: Labels,
    pub data_licenses: Vec<String>,

    #[schema(required)]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    pub authors: Vec<String>,

    pub name: String,
}

impl SbomHead {
    pub async fn from_entity(
        sbom: &sbom::Model,
        sbom_node: Option<sbom_node::Model>,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            id: sbom.sbom_id,
            document_id: sbom.document_id.clone(),
            labels: sbom.labels.clone(),
            published: sbom.published,
            authors: sbom.authors.clone(),
            name: sbom_node
                .map(|node| node.name.clone())
                .unwrap_or("".to_string()),
            data_licenses: sbom.data_licenses.clone(),
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomSummary {
    #[serde(flatten)]
    pub head: SbomHead,

    #[serde(flatten)]
    pub source_document: Option<SourceDocument>,

    pub described_by: Vec<SbomPackage>,

    /// The number of packages this SBOM has
    pub number_of_packages: u64,
}

impl SbomSummary {
    pub async fn from_entity(
        (sbom, node): (sbom::Model, Option<sbom_node::Model>),
        service: &SbomService,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Option<SbomSummary>, Error> {
        // TODO: consider improving the n-select issues here
        let described_by = service
            .describes_packages(sbom.sbom_id, Paginated::default(), ())
            .await?
            .items;

        let source_document = sbom.find_related(source_document::Entity).one(tx).await?;
        let number_of_packages = sbom.find_related(sbom_package::Entity).count(tx).await?;

        Ok(match node {
            Some(_) => Some(SbomSummary {
                head: SbomHead::from_entity(&sbom, node, tx).await?,
                source_document: if let Some(doc) = &source_document {
                    Some(SourceDocument::from_entity(doc, tx).await?)
                } else {
                    None
                },
                described_by,
                number_of_packages,
            }),
            None => None,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, SimpleObject)]
#[graphql(concrete(name = "SbomPackage", params()))]
pub struct SbomPackage {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    #[graphql(skip)]
    pub purl: Vec<PurlSummary>,
    pub cpe: Vec<String>,
}

// TODO: think about a way to add CPE and PURLs too
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SbomPackageReference<'a> {
    /// Reference all packages of the SBOM.
    All,
    /// Reference a package inside an SBOM, by its node id.
    Package(&'a str),
}

impl<'a> From<&'a str> for SbomPackageReference<'a> {
    fn from(value: &'a str) -> Self {
        Self::Package(value)
    }
}

impl<'a> From<()> for SbomPackageReference<'a> {
    fn from(_value: ()) -> Self {
        Self::All
    }
}

impl<'a> From<&'a SbomPackage> for SbomPackageReference<'a> {
    fn from(value: &'a SbomPackage) -> Self {
        Self::Package(&value.id)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SbomPackageRelation {
    pub relationship: Relationship,
    pub package: SbomPackage,
}

#[derive(Clone, Eq, PartialEq, Default, Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Which {
    /// Originating side
    #[default]
    Left,
    /// Target side
    Right,
}
