use crate::organization::model::OrganizationSummary;
use crate::product::model::{ProductHead, ProductVersionHead};
use crate::Error;
use itertools::izip;
use sea_orm::LoaderTrait;
use sea_orm::ModelTrait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::labels::Labels;
use trustify_entity::{organization, product, product_version, sbom};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProductDetails {
    #[serde(flatten)]
    pub head: ProductHead,
    pub versions: Vec<ProductVersionDetails>,
    #[schema(required)]
    pub vendor: Option<OrganizationSummary>,
}

impl ProductDetails {
    pub async fn from_entity(
        product: &product::Model,
        org: Option<organization::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let product_versions = product
            .find_related(product_version::Entity)
            .all(tx)
            .await?;
        let vendor = if let Some(org) = org {
            Some(OrganizationSummary::from_entity(&org, tx).await?)
        } else {
            None
        };
        Ok(ProductDetails {
            head: ProductHead::from_entity(product, tx).await?,
            versions: ProductVersionDetails::from_entities(&product_versions, tx).await?,
            vendor,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ProductVersionDetails {
    #[serde(flatten)]
    pub head: ProductVersionHead,
    pub sbom: Option<ProductSbomHead>,
}

impl ProductVersionDetails {
    pub async fn from_entity(
        product_version: &product_version::Model,
        sbom: Option<sbom::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let sbom = if let Some(sbom) = sbom {
            Some(ProductSbomHead::from_entity(&sbom, tx).await?)
        } else {
            None
        };

        Ok(ProductVersionDetails {
            head: ProductVersionHead::from_entity(product_version, tx).await?,
            sbom,
        })
    }

    pub async fn from_entities(
        product_versions: &[product_version::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut details = Vec::new();
        let sboms = product_versions.load_one(sbom::Entity, tx).await?;

        for (version, sbom) in izip!(product_versions, sboms) {
            details.push(ProductVersionDetails::from_entity(version, sbom, tx).await?);
        }

        Ok(details)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ProductSbomHead {
    pub labels: Labels,
    #[schema(required)]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,
}

impl ProductSbomHead {
    pub async fn from_entity(
        sbom: &trustify_entity::sbom::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(ProductSbomHead {
            labels: sbom.labels.clone(),
            published: sbom.published,
        })
    }
}
