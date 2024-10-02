//! Support for SBOMs.

pub mod cyclonedx;
pub mod spdx;

pub mod clearly_defined;

mod common;
pub use common::*;

use super::error::Error;
use crate::{
    db::{LeftPackageId, QualifiedPackageTransitive},
    graph::{
        cpe::CpeContext,
        product::{product_version::ProductVersionContext, ProductContext},
        purl::{creator::PurlCreator, qualified_package::QualifiedPackageContext},
        Graph,
    },
};
use cpe::uri::OwnedUri;
use entity::{product, product_version};
use hex::ToHex;
use sea_orm::{
    prelude::Uuid, ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter,
    QuerySelect, QueryTrait, RelationTrait, Select, SelectColumns, Set,
};
use sea_query::{
    extension::postgres::PgExpr, Alias, Condition, Expr, Func, JoinType, Query, SimpleExpr,
};
use std::{
    fmt::{Debug, Formatter},
    iter,
    str::FromStr,
};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{
    cpe::Cpe, db::Transactional, hashing::Digests, purl::Purl, sbom::SbomLocator,
};
use trustify_entity::{
    self as entity, labels::Labels, license, package_relates_to_package, purl_license_assertion,
    relationship::Relationship, sbom, sbom_node, sbom_package, sbom_package_cpe_ref,
    sbom_package_purl_ref, source_document,
};

#[derive(Clone, Default)]
pub struct SbomInformation {
    /// The id of the document in the SBOM graph
    pub node_id: String,
    /// The name of the document/node
    pub name: String,
    pub published: Option<OffsetDateTime>,
    pub authors: Vec<String>,
}

impl From<()> for SbomInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

type SelectEntity<E> = Select<E>;

impl Graph {
    pub async fn get_sbom_by_id<TX: AsRef<Transactional>>(
        &self,
        id: Uuid,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(sbom::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    #[instrument(skip(tx))]
    pub async fn get_sbom_by_digest<TX: AsRef<Transactional>>(
        &self,
        digest: &str,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(entity::sbom::Entity::find()
            .join(
                JoinType::LeftJoin,
                entity::sbom::Relation::SourceDocument.def(),
            )
            .filter(
                Condition::any()
                    .add(source_document::Column::Sha256.eq(digest.to_string()))
                    .add(source_document::Column::Sha384.eq(digest.to_string()))
                    .add(source_document::Column::Sha512.eq(digest.to_string())),
            )
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    #[instrument(skip(tx, info), err(level=tracing::Level::INFO))]
    pub async fn ingest_sbom<TX: AsRef<Transactional>>(
        &self,
        labels: impl Into<Labels> + Debug,
        digests: &Digests,
        document_id: &str,
        info: impl Into<SbomInformation>,
        tx: TX,
    ) -> Result<SbomContext, Error> {
        let sha256 = digests.sha256.encode_hex::<String>();

        if let Some(found) = self.get_sbom_by_digest(&sha256, &tx).await? {
            return Ok(found);
        }

        let SbomInformation {
            node_id,
            name,
            published,
            authors,
        } = info.into();

        let connection = self.db.connection(&tx);

        let sbom_id = Uuid::now_v7();

        let doc_model = source_document::ActiveModel {
            id: Default::default(),
            sha256: Set(sha256),
            sha384: Set(digests.sha384.encode_hex()),
            sha512: Set(digests.sha512.encode_hex()),
        };

        let doc = doc_model.insert(&connection).await?;

        let model = sbom::ActiveModel {
            sbom_id: Set(sbom_id),
            node_id: Set(node_id.clone()),

            document_id: Set(document_id.to_string()),

            published: Set(published),
            authors: Set(authors),

            source_document_id: Set(Some(doc.id)),
            labels: Set(labels.into()),
        };

        let node_model = sbom_node::ActiveModel {
            sbom_id: Set(sbom_id),
            node_id: Set(node_id),
            name: Set(name),
        };

        let result = model.insert(&connection).await?;
        node_model.insert(&connection).await?;

        Ok(SbomContext::new(self, result))
    }

    /// Fetch a single SBOM located via internal `id`, external `location` (URL),
    /// described pURL, described CPE, or sha256 hash.
    ///
    /// Fetching by pURL, CPE or location may result in a single result where multiple
    /// may exist in the fetch in actuality.
    ///
    /// If the requested SBOM does not exist in the fetch, it will not exist
    /// after this query either. This function is *non-mutating*.
    pub async fn locate_sbom<TX: AsRef<Transactional>>(
        &self,
        sbom_locator: SbomLocator,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        match sbom_locator {
            SbomLocator::Id(id) => self.locate_sbom_by_id(id, tx).await,
            SbomLocator::Sha256(sha256) => self.locate_sbom_by_sha256(&sha256, tx).await,
            SbomLocator::Purl(purl) => self.locate_sbom_by_purl(&purl, tx).await,
            SbomLocator::Cpe(cpe) => self.locate_sbom_by_cpe22(&cpe, tx).await,
        }
    }

    pub async fn locate_sboms<TX: AsRef<Transactional>>(
        &self,
        sbom_locator: SbomLocator,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        match sbom_locator {
            SbomLocator::Id(id) => {
                if let Some(sbom) = self.locate_sbom_by_id(id, tx).await? {
                    Ok(vec![sbom])
                } else {
                    Ok(vec![])
                }
            }
            SbomLocator::Sha256(sha256) => self.locate_sboms_by_sha256(&sha256, tx).await,
            SbomLocator::Purl(purl) => self.locate_sboms_by_purl(&purl, tx).await,
            SbomLocator::Cpe(cpe) => self.locate_sboms_by_cpe22(cpe, tx).await,
        }
    }

    async fn locate_one_sbom<TX: AsRef<Transactional>>(
        &self,
        query: SelectEntity<sbom::Entity>,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(query
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    pub async fn locate_many_sboms<TX: AsRef<Transactional>>(
        &self,
        query: SelectEntity<sbom::Entity>,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        Ok(query
            .all(&self.connection(&tx))
            .await?
            .into_iter()
            .map(|sbom| SbomContext::new(self, sbom))
            .collect())
    }

    pub async fn locate_sbom_by_id<TX: AsRef<Transactional>>(
        &self,
        id: Uuid,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        let _query = sbom::Entity::find_by_id(id);
        Ok(sbom::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    pub async fn locate_sboms_by_labels<TX: AsRef<Transactional>>(
        &self,
        labels: Labels,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            sbom::Entity::find().filter(Expr::col(sbom::Column::Labels).contains(labels)),
            tx,
        )
        .await
    }

    async fn locate_sbom_by_sha256<TX: AsRef<Transactional>>(
        &self,
        sha256: &str,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        self.locate_one_sbom(
            sbom::Entity::find()
                .join(JoinType::Join, sbom::Relation::SourceDocument.def())
                .filter(source_document::Column::Sha256.eq(sha256.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sboms_by_sha256<TX: AsRef<Transactional>>(
        &self,
        sha256: &str,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            sbom::Entity::find()
                .join(JoinType::Join, sbom::Relation::SourceDocument.def())
                .filter(source_document::Column::Sha256.eq(sha256.to_string())),
            tx,
        )
        .await
    }

    fn query_by_purl(package: QualifiedPackageContext) -> Select<sbom::Entity> {
        entity::sbom::Entity::find()
            .join_rev(JoinType::Join, sbom_package::Relation::Sbom.def())
            .join_rev(
                JoinType::Join,
                sbom_package_purl_ref::Relation::Package.def(),
            )
            .filter(sbom_package_purl_ref::Column::QualifiedPurlId.eq(package.qualified_package.id))
    }

    fn query_by_cpe(cpe: CpeContext) -> Select<sbom::Entity> {
        entity::sbom::Entity::find()
            .join_rev(JoinType::Join, sbom_package::Relation::Sbom.def())
            .join_rev(
                JoinType::Join,
                sbom_package_cpe_ref::Relation::Package.def(),
            )
            .filter(sbom_package_cpe_ref::Column::CpeId.eq(cpe.cpe.id))
    }

    async fn locate_sbom_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, &tx).await?;

        if let Some(package) = package {
            self.locate_one_sbom(Self::query_by_purl(package), &tx)
                .await
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self, tx), err(level=tracing::Level::INFO))]
    async fn locate_sboms_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, &tx).await?;

        if let Some(package) = package {
            self.locate_many_sboms(Self::query_by_purl(package), &tx)
                .await
        } else {
            Ok(vec![])
        }
    }

    #[instrument(skip(self, tx), err(level=tracing::Level::INFO))]
    async fn locate_sbom_by_cpe22<TX: AsRef<Transactional>>(
        &self,
        cpe: &Cpe,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        if let Some(cpe) = self.get_cpe(cpe.clone(), &tx).await? {
            self.locate_one_sbom(Self::query_by_cpe(cpe), &tx).await
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self, tx), err)]
    async fn locate_sboms_by_cpe22<C, TX>(&self, cpe: C, tx: TX) -> Result<Vec<SbomContext>, Error>
    where
        C: Into<Cpe> + Debug,
        TX: AsRef<Transactional>,
    {
        if let Some(cpe) = self.get_cpe(cpe, &tx).await? {
            self.locate_many_sboms(Self::query_by_cpe(cpe), &tx).await
        } else {
            Ok(vec![])
        }
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
enum RelationshipReference {
    Root,
    Purl(Purl),
    Cpe(Cpe),
}

impl From<()> for RelationshipReference {
    fn from(_: ()) -> Self {
        Self::Root
    }
}

impl From<Purl> for RelationshipReference {
    fn from(value: Purl) -> Self {
        Self::Purl(value)
    }
}

impl From<Cpe> for RelationshipReference {
    fn from(value: Cpe) -> Self {
        Self::Cpe(value)
    }
}

impl FromStr for RelationshipReference {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(purl) = Purl::from_str(s) {
            return Ok(Self::Purl(purl));
        }

        if let Ok(cpe) = OwnedUri::from_str(s) {
            return Ok(Self::Cpe(cpe.into()));
        }

        Err(())
    }
}

#[derive(Clone)]
pub struct SbomContext {
    pub graph: Graph,
    pub sbom: sbom::Model,
}

impl PartialEq for SbomContext {
    fn eq(&self, other: &Self) -> bool {
        self.sbom.eq(&other.sbom)
    }
}

impl Debug for SbomContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.sbom.fmt(f)
    }
}

impl SbomContext {
    pub fn new(graph: &Graph, sbom: sbom::Model) -> Self {
        Self {
            graph: graph.clone(),
            sbom,
        }
    }

    pub async fn ingest_purl_license_assertion<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
        license: &str,
        tx: TX,
    ) -> Result<(), Error> {
        let connection = self.graph.connection(&tx);
        let purl = self.graph.ingest_qualified_package(purl, &tx).await?;

        let license_info = LicenseInfo {
            license: license.to_string(),
            refs: Default::default(),
        };

        let (spdx_licenses, spdx_exceptions) = license_info.spdx_info();

        let license = license::Entity::find_by_id(license_info.uuid())
            .one(&connection)
            .await?;

        let license = if let Some(license) = license {
            license
        } else {
            license::ActiveModel {
                id: Set(license_info.uuid()),
                text: Set(license_info.license.clone()),
                spdx_licenses: if spdx_licenses.is_empty() {
                    Set(None)
                } else {
                    Set(Some(spdx_licenses))
                },
                spdx_license_exceptions: if spdx_exceptions.is_empty() {
                    Set(None)
                } else {
                    Set(Some(spdx_exceptions))
                },
            }
            .insert(&connection)
            .await?
        };

        let assertion = purl_license_assertion::Entity::find()
            .filter(purl_license_assertion::Column::LicenseId.eq(license.id))
            .filter(
                purl_license_assertion::Column::VersionedPurlId
                    .eq(purl.package_version.package_version.id),
            )
            .filter(purl_license_assertion::Column::SbomId.eq(self.sbom.sbom_id))
            .one(&connection)
            .await?;

        if assertion.is_none() {
            purl_license_assertion::ActiveModel {
                id: Default::default(),
                license_id: Set(license.id),
                versioned_purl_id: Set(purl.package_version.package_version.id),
                sbom_id: Set(self.sbom.sbom_id),
            }
            .insert(&connection)
            .await?;
        }

        Ok(())
    }

    /// Get the packages which describe an SBOM
    ///
    /// This is supposed to return a query, returning all sbom_packages which describe an SBOM.
    fn query_describes_packages(&self) -> Select<sbom_package::Entity> {
        sbom_package::Entity::find()
            .filter(sbom::Column::SbomId.eq(self.sbom.sbom_id))
            .filter(package_relates_to_package::Column::Relationship.eq(Relationship::DescribedBy))
            .select_only()
            .join(JoinType::Join, sbom_package::Relation::Sbom.def())
            .join(JoinType::Join, sbom_package::Relation::Node.def())
            .join_rev(
                JoinType::Join,
                package_relates_to_package::Relation::Right.def(),
            )
            .join_as(
                JoinType::Join,
                package_relates_to_package::Relation::Left.def(),
                Alias::new("source"),
            )
    }

    /// Get the PURLs which describe an SBOM
    #[instrument(skip(tx), err)]
    pub async fn describes_purls<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let describes = self.query_describes_packages();

        self.graph
            .get_qualified_packages_by_query(
                describes
                    .join(JoinType::Join, sbom_package::Relation::Purl.def())
                    .select_column(sbom_package_purl_ref::Column::QualifiedPurlId)
                    .into_query(),
                tx,
            )
            .await
    }

    /// Get the CPEs which describe an SBOM
    #[instrument(skip(tx), err)]
    pub async fn describes_cpe22s<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<CpeContext>, Error> {
        let describes = self.query_describes_packages();

        self.graph
            .get_cpe_by_query(
                describes
                    .join(JoinType::Join, sbom_package::Relation::Cpe.def())
                    .select_column(sbom_package_cpe_ref::Column::CpeId)
                    .into_query(),
                tx,
            )
            .await
    }

    /*
        #[instrument(skip(tx), err)]
        pub async fn packages<TX: AsRef<Transactional>>(
            &self,
            tx: TX,
        ) -> Result<Vec<QualifiedPackageContext>, Error> {
            self.graph
                .get_qualified_packages_by_query(
                    entity::sbom_package::Entity::find()
                        .select_only()
                        .column(entity::sbom_package::Column::QualifiedPackageId)
                        .filter(entity::sbom_package::Column::SbomId.eq(self.sbom.id))
                        .into_query(),
                    tx,
                )
                .await
        }
    */

    /// Within the context of *this* SBOM, ingest a relationship between
    /// two packages.
    ///
    /// The packages will be created if they don't yet exist.
    ///
    /// **NOTE:** This is a convenience function, creating relationships for tests. It is terribly slow.
    #[instrument(skip(tx), err)]
    pub async fn ingest_package_relates_to_package<'a, TX: AsRef<Transactional>>(
        &'a self,
        left: impl Into<RelationshipReference> + Debug,
        relationship: Relationship,
        right: impl Into<RelationshipReference> + Debug,
        tx: TX,
    ) -> Result<(), Error> {
        let left = left.into();
        let right = right.into();

        // ensure the PURLs and CPEs exist first

        let mut creator = PurlCreator::new();
        let (left_node_id, left_purls, left_cpes) = match left {
            RelationshipReference::Root => (None, vec![], vec![]),
            RelationshipReference::Purl(purl) => {
                creator.add(purl.clone());
                (
                    Some(purl.to_string()),
                    vec![(purl.version_uuid(), purl.qualifier_uuid())],
                    vec![],
                )
            }
            RelationshipReference::Cpe(cpe) => {
                let cpe_ctx = self.graph.ingest_cpe22(cpe.clone(), &tx).await?;
                (Some(cpe.to_string()), vec![], vec![cpe_ctx.cpe.id])
            }
        };
        let (right_node_id, right_purls, right_cpes) = match right {
            RelationshipReference::Root => (None, vec![], vec![]),
            RelationshipReference::Purl(purl) => {
                creator.add(purl.clone());
                (
                    Some(purl.to_string()),
                    vec![(purl.version_uuid(), purl.qualifier_uuid())],
                    vec![],
                )
            }
            RelationshipReference::Cpe(cpe) => {
                let cpe_ctx = self.graph.ingest_cpe22(cpe.clone(), &tx).await?;
                (Some(cpe.to_string()), vec![], vec![cpe_ctx.cpe.id])
            }
        };

        creator.create(&self.graph.connection(&tx)).await?;

        // create the nodes

        if let Some(left_node_id) = left_node_id.clone() {
            self.ingest_package(
                left_node_id.clone(),
                left_node_id.clone(),
                None,
                left_purls,
                left_cpes,
                &tx,
            )
            .await?;
        }

        if let Some(right_node_id) = right_node_id.clone() {
            self.ingest_package(
                right_node_id.clone(),
                right_node_id.clone(),
                None,
                right_purls,
                right_cpes,
                &tx,
            )
            .await?;
        }

        // now create the relationship

        let left_node_id = left_node_id.unwrap_or_else(|| self.sbom.node_id.clone());
        let right_node_id = right_node_id.unwrap_or_else(|| self.sbom.node_id.clone());

        let mut relationships = RelationshipCreator::new(self.sbom.sbom_id);
        relationships.relate(left_node_id, relationship, right_node_id);
        relationships.create(&self.graph.db.connection(&tx)).await?;

        Ok(())
    }

    #[instrument(skip(self, tx), err)]
    pub async fn ingest_describes_package<TX: AsRef<Transactional>>(
        &self,
        package: Purl,
        tx: TX,
    ) -> anyhow::Result<()> {
        self.ingest_package_relates_to_package(
            RelationshipReference::Root,
            Relationship::DescribedBy,
            RelationshipReference::Purl(package),
            tx,
        )
        .await?;
        Ok(())
    }

    #[instrument(skip(self, tx), err)]
    pub async fn ingest_describes_cpe22<TX: AsRef<Transactional>>(
        &self,
        cpe: Cpe,
        tx: TX,
    ) -> anyhow::Result<()> {
        self.ingest_package_relates_to_package(
            RelationshipReference::Root,
            Relationship::DescribedBy,
            RelationshipReference::Cpe(cpe),
            tx,
        )
        .await?;
        Ok(())
    }

    /// Ingest a single package for this SBOM.
    ///
    /// **NOTE:** This function ingests a single package, and is terribly slow.
    /// Use the [`PackageCreator`] for creating more than one.
    #[instrument(skip(self, tx), err)]
    async fn ingest_package<TX: AsRef<Transactional>>(
        &self,
        node_id: String,
        name: String,
        version: Option<String>,
        purls: Vec<(Uuid, Uuid)>,
        cpes: Vec<Uuid>,
        tx: TX,
    ) -> Result<(), Error> {
        let mut creator = PackageCreator::new(self.sbom.sbom_id);

        let refs = purls
            .into_iter()
            .map(|(versioned_purl, qualified_purl)| PackageReference::Purl {
                versioned_purl,
                qualified_purl,
            })
            .chain(cpes.into_iter().map(PackageReference::Cpe));
        creator.add(node_id, name, version, refs, iter::empty());

        creator.create(&self.graph.db.connection(&tx)).await?;

        // done

        Ok(())
    }

    #[instrument(skip(self, tx), err)]
    pub async fn related_packages_transitively<TX: AsRef<Transactional>>(
        &self,
        relationships: &[Relationship],
        pkg: &Purl,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let pkg = self.graph.get_qualified_package(pkg, &tx).await?;

        if let Some(pkg) = pkg {
            let rels: SimpleExpr = relationships
                .iter()
                .map(|e| (*e) as i32)
                .collect::<Vec<_>>()
                .into();

            let sbom_id: SimpleExpr = self.sbom.sbom_id.into();
            let qualified_package_id: SimpleExpr = pkg.qualified_package.id.into();

            Ok(self
                .graph
                .get_qualified_packages_by_query(
                    Query::select()
                        .column(LeftPackageId)
                        .from_function(
                            Func::cust(QualifiedPackageTransitive).args([
                                sbom_id,
                                qualified_package_id,
                                rels,
                            ]),
                            QualifiedPackageTransitive,
                        )
                        .to_owned(),
                    &tx,
                )
                .await?)
        } else {
            Ok(vec![])
        }
    }

    pub async fn link_to_product<'a, TX: AsRef<Transactional>>(
        &self,
        product_version: ProductVersionContext<'a>,
        tx: TX,
    ) -> Result<ProductVersionContext<'a>, Error> {
        let mut entity = product_version::ActiveModel::from(product_version.product_version);
        entity.sbom_id = Set(Some(self.sbom.sbom_id));
        let model = entity.update(&self.graph.connection(&tx)).await?;
        Ok(ProductVersionContext::new(&product_version.product, model))
    }

    pub async fn get_product<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Option<ProductVersionContext>, Error> {
        if let Some(vers) = product_version::Entity::find()
            .filter(product_version::Column::SbomId.eq(self.sbom.sbom_id))
            .one(&self.graph.connection(&tx))
            .await?
        {
            if let Some(prod) = vers
                .find_related(product::Entity)
                .one(&self.graph.connection(&tx))
                .await?
            {
                Ok(Some(ProductVersionContext::new(
                    &ProductContext::new(&self.graph, prod),
                    vers,
                )))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /*

    pub async fn direct_dependencies(&self, tx: Transactional<'_>) -> Result<Vec<Purl>, Error> {
        let found = package::Entity::find()
            .join(
                JoinType::LeftJoin,
                sbom_dependency::Relation::Package.def().rev(),
            )
            .filter(sbom_dependency::Column::SbomId.eq(self.sbom.id))
            .find_with_related(package_qualifier::Entity)
            .all(&self.fetch.connection(tx))
            .await?;

        Ok(packages_to_purls(found)?)
    }

     */
}
