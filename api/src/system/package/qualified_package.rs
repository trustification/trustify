use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::package::package_version::PackageVersionContext;
use huevos_common::package::{Assertion, VulnerabilityAssertions};
use huevos_common::purl::Purl;
use huevos_entity as entity;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, RelationTrait};
use sea_query::JoinType;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct QualifiedPackageContext {
    pub(crate) package_version: PackageVersionContext,
    pub(crate) qualified_package: entity::qualified_package::Model,
    // just a short-cut to avoid another query
    pub(crate) qualifiers: HashMap<String, String>,
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
    pub async fn vulnerability_assertions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<VulnerabilityAssertions, Error> {
        let possible_affected_assertions =
            self.package_version.package.affected_assertions(tx).await?;

        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::system::InnerSystem;

    #[ignore]
    #[tokio::test]
    async fn vulnerability_assertions() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("vulnerability_assertions").await?;

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                Transactional::None,
            )
            .await?;

        let affected_core = advisory
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let affected_addons = advisory
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
}
