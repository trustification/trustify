pub mod details;

use crate::purl::model::summary::purl::PurlSummary;
use async_graphql::SimpleObject;
use sea_orm::prelude::Uuid;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::{id::Id, paginated};
use trustify_entity::{labels::Labels, relationship::Relationship};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomHead {
    #[serde(with = "uuid::serde::urn")]
    pub id: Uuid,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<Id>,

    pub document_id: String,
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,

    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomSummary {
    #[serde(flatten)]
    pub head: SbomHead,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub described_by: Vec<SbomPackage>,
}

paginated!(SbomSummary);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, SimpleObject)]
#[graphql(concrete(name = "SbomPackage", params()))]
pub struct SbomPackage {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[graphql(skip)]
    pub purl: Vec<PurlSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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

paginated!(SbomPackage);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SbomPackageRelation {
    pub relationship: Relationship,
    pub package: SbomPackage,
}

paginated!(SbomPackageRelation);

#[derive(Clone, Eq, PartialEq, Default, Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Which {
    /// Originating side
    #[default]
    Left,
    /// Target side
    Right,
}
