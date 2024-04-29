//! Support for a *fully-qualified* package.

use crate::graph::error::Error;
use crate::graph::package::package_version::PackageVersionContext;
use crate::graph::sbom::SbomContext;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use trustify_common::db::Transactional;
use trustify_common::package::PackageVulnerabilityAssertions;
use trustify_common::purl::Purl;
use trustify_entity as entity;
use trustify_entity::qualified_package;

#[derive(Clone)]
pub struct QualifiedPackageContext<'g> {
    pub package_version: PackageVersionContext<'g>,
    pub qualified_package: entity::qualified_package::Model,
}

impl PartialEq for QualifiedPackageContext<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.qualified_package.eq(&other.qualified_package)
    }
}

impl Eq for QualifiedPackageContext<'_> {}

impl Hash for QualifiedPackageContext<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.qualified_package.id.as_bytes());
    }
}

impl Debug for QualifiedPackageContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.qualified_package.fmt(f)
    }
}

impl<'g> From<QualifiedPackageContext<'g>> for Purl {
    fn from(value: QualifiedPackageContext<'g>) -> Self {
        Self {
            ty: value.package_version.package.package.r#type,
            namespace: value.package_version.package.package.namespace,
            name: value.package_version.package.package.name,
            version: Some(value.package_version.package_version.version),
            qualifiers: BTreeMap::from_iter(value.qualified_package.qualifiers.0),
        }
    }
}

impl<'g> QualifiedPackageContext<'g> {
    pub fn new(
        package_version: &PackageVersionContext<'g>,
        qualified_package: qualified_package::Model,
    ) -> Self {
        Self {
            package_version: package_version.clone(),
            qualified_package,
        }
    }
    pub async fn sboms_containing<TX: AsRef<Transactional>>(
        &self,
        _tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
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
            .all(&self.package_version.package.fetch.connection(tx))
            .await?
            .drain(0..)
            .map(|sbom| (&self.package_version.package.fetch, sbom).into())
            .collect())

         */
        todo!()
    }

    pub async fn vulnerability_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        let affected = self.affected_assertions(&tx).await?;
        let not_affected = self.not_affected_assertions(&tx).await?;

        let mut merged = PackageVulnerabilityAssertions::default();

        merged.assertions.extend_from_slice(&affected.assertions);

        merged
            .assertions
            .extend_from_slice(&not_affected.assertions);

        Ok(merged)
    }

    pub async fn affected_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        self.package_version.affected_assertions(tx).await
    }

    pub async fn not_affected_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        self.package_version.not_affected_assertions(tx).await
    }
}

#[cfg(test)]
mod tests {
    use crate::graph::Graph;
    use test_context::test_context;
    use trustify_common::db::{test::TrustifyContext, Transactional};

    #[test_context(TrustifyContext, skip_teardown)]
    #[tokio::test]
    async fn vulnerability_assertions(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                (),
                Transactional::None,
            )
            .await?;

        let advisory_vulnerability = advisory
            .link_to_vulnerability("CVE-2", Transactional::None)
            .await?;

        let _affected_core = advisory_vulnerability
            .ingest_affected_package_range(
                &"pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let _affected_addons = advisory_vulnerability
            .ingest_affected_package_range(
                &"pkg://maven/io.quarkus/quarkus-addons".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let pkg_core = system
            .ingest_qualified_package(
                &"pkg://maven/io.quarkus/quarkus-core@1.0.4".try_into()?,
                Transactional::None,
            )
            .await?;

        pkg_core
            .vulnerability_assertions(Transactional::None)
            .await?;

        let _pkg_addons = system
            .ingest_qualified_package(
                &"pkg://maven/io.quarkus/quarkus-core@1.0.4".try_into()?,
                Transactional::None,
            )
            .await?;

        Ok(())
    }

    /*
    #[tokio::test]
    async fn sboms_containing() -> Result<(), anyhow::Error> {
        let fetch = InnerSystem::for_test("sboms_containing").await?;

        let sbom1 = fetch
            .ingest_sbom("http://sbom.com/one.json", "1", Transactional::None)
            .await?;

        let sbom2 = fetch
            .ingest_sbom("http://sbom.com/two.json", "2", Transactional::None)
            .await?;

        let sbom3 = fetch
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

        let pkg = fetch
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
