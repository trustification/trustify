//! Support for a *fully-qualified* package.

use crate::db::Transactional;
use crate::graph::error::Error;
use crate::graph::package::package_version::PackageVersionContext;
use crate::graph::sbom::SbomContext;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, RelationTrait};
use sea_query::JoinType;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use trustify_common::package::{Assertion, PackageVulnerabilityAssertions};
use trustify_common::purl::Purl;
use trustify_entity as entity;

#[derive(Clone)]
pub struct QualifiedPackageContext {
    pub(crate) package_version: PackageVersionContext,
    pub(crate) qualified_package: entity::qualified_package::Model,
    // just a short-cut to avoid another query
    pub(crate) qualifiers: HashMap<String, String>,
}

impl PartialEq for QualifiedPackageContext {
    fn eq(&self, other: &Self) -> bool {
        self.qualified_package.eq(&other.qualified_package)
    }
}

impl Eq for QualifiedPackageContext {}

impl Hash for QualifiedPackageContext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_i32(self.qualified_package.id)
    }
}

impl Debug for QualifiedPackageContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.qualified_package.fmt(f)
    }
}

impl
    From<(
        &PackageVersionContext,
        entity::qualified_package::Model,
        HashMap<String, String>,
    )> for QualifiedPackageContext
{
    fn from(
        (package_version, qualified_package, qualifiers): (
            &PackageVersionContext,
            entity::qualified_package::Model,
            HashMap<String, String>,
        ),
    ) -> Self {
        Self {
            package_version: package_version.clone(),
            qualified_package,
            qualifiers,
        }
    }
}

impl From<QualifiedPackageContext> for Purl {
    fn from(value: QualifiedPackageContext) -> Self {
        Self {
            ty: value.package_version.package.package.r#type.clone(),
            namespace: value.package_version.package.package.namespace.clone(),
            name: value.package_version.package.package.name.clone(),
            version: Some(value.package_version.package_version.version.clone()),
            qualifiers: value.qualifiers.clone(),
        }
    }
}

impl QualifiedPackageContext {
    pub async fn sboms_containing(&self, tx: Transactional<'_>) -> Result<Vec<SbomContext>, Error> {
        /*
        Ok(entity::sbom::Entity::find()
            .join(
                JoinType::Join,
                entity::sbom_contains_package::Relation::Sbom.def().rev(),
            )
            .filter(
                entity::sbom_contains_package::Column::QualifiedPackageId
                    .eq(self.qualified_package.id),
            )
            .all(&self.package_version.package.graph.connection(tx))
            .await?
            .drain(0..)
            .map(|sbom| (&self.package_version.package.graph, sbom).into())
            .collect())

         */
        todo!()
    }

    pub async fn vulnerability_assertions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        let affected = self.affected_assertions(tx).await?;
        let not_affected = self.not_affected_assertions(tx).await?;

        let mut merged = PackageVulnerabilityAssertions::default();

        merged.assertions.extend_from_slice(&affected.assertions);

        merged
            .assertions
            .extend_from_slice(&not_affected.assertions);

        Ok(merged)
    }

    pub async fn affected_assertions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        self.package_version.affected_assertions(tx).await
    }

    pub async fn not_affected_assertions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        self.package_version.not_affected_assertions(tx).await
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::graph::{Graph, InnerGraph};

    #[ignore]
    #[tokio::test]
    async fn vulnerability_assertions() -> Result<(), anyhow::Error> {
        let system = Graph::for_test("vulnerability_assertions").await?;

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                Transactional::None,
            )
            .await?;

        let advisory_vulnerability = advisory
            .ingest_vulnerability("CVE-2", Transactional::None)
            .await?;

        let affected_core = advisory_vulnerability
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let affected_addons = advisory_vulnerability
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-addons",
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let pkg_core = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.0.4",
                Transactional::None,
            )
            .await?;

        pkg_core
            .vulnerability_assertions(Transactional::None)
            .await?;

        let pkg_addons = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.0.4",
                Transactional::None,
            )
            .await?;

        Ok(())
    }

    /*
    #[tokio::test]
    async fn sboms_containing() -> Result<(), anyhow::Error> {
        let graph = InnerSystem::for_test("sboms_containing").await?;

        let sbom1 = graph
            .ingest_sbom("http://sbom.com/one.json", "1", Transactional::None)
            .await?;

        let sbom2 = graph
            .ingest_sbom("http://sbom.com/two.json", "2", Transactional::None)
            .await?;

        let sbom3 = graph
            .ingest_sbom("http://sbom.com/three.json", "3", Transactional::None)
            .await?;

        sbom1
            .ingest_contains_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        sbom2
            .ingest_contains_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        sbom3
            .ingest_contains_package(
                "pkg://maven/io.quarkus/NOT_QUARKUS@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg = graph
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let sboms = pkg.sboms_containing(Transactional::None).await?;

        assert_eq!(2, sboms.len());

        assert!(sboms.contains(&sbom1));
        assert!(sboms.contains(&sbom2));
        Ok(())
    }

     */
}
