use huevos_common::purl::{Purl, PurlErr};
use huevos_common::sbom::SbomLocator;
use huevos_entity::package::{Model, PackageNamespace, PackageType};
use huevos_entity::sbom::Column;
use huevos_entity::{
    package, package_dependency, package_qualifier, package_version, package_version_range,
    qualified_package, sbom, sbom_describes_package,
};
use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, FromQueryResult,
    ModelTrait, QueryFilter, QuerySelect, Select, Set,
};
use sea_orm::{RelationTrait, TransactionTrait};
use sea_query::{JoinType, Query};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::sbom::SbomContext;
use crate::system::InnerSystem;

impl InnerSystem {
    pub async fn ingest_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<QualifiedPackageContext, Error> {
        let purl = pkg.into();
        let package_version = self.ingest_package_version(purl.clone(), tx).await?;

        package_version
            .ingest_qualified_package(purl.clone(), tx)
            .await
    }

    pub async fn ingest_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionContext, Error> {
        let pkg = pkg.into();
        let package = self.ingest_package(pkg.clone(), tx).await?;

        package.ingest_package_version(pkg.clone(), tx).await
    }

    pub async fn ingest_package_version_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionRangeContext, Error> {
        let pkg = pkg.into();
        let package = self.ingest_package(pkg.clone(), tx).await?;

        package
            .ingest_package_version_range(pkg.clone(), start, end, tx)
            .await
    }

    pub async fn ingest_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<PackageContext, Error> {
        let purl = pkg.into();

        if let Some(found) = self.get_package(purl.clone(), tx.clone()).await? {
            Ok(found)
        } else {
            let model = package::ActiveModel {
                id: Default::default(),
                r#type: Set(purl.ty.clone()),
                namespace: Set(purl.namespace.clone()),
                name: Set(purl.name.clone()),
            };

            Ok((self, model.insert(&self.connection(tx)).await?).into())
        }
    }

    pub async fn get_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<QualifiedPackageContext>, Error> {
        let purl = pkg.into();
        if let Some(package_version) = self.get_package_version(purl.clone(), tx.clone()).await? {
            package_version.get_qualified_package(purl, tx).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionContext>, Error> {
        let purl = pkg.into();
        if let Some(pkg) = self.get_package(purl.clone(), tx).await? {
            pkg.get_package_version(purl, tx).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_package_version_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionRangeContext>, Error> {
        let purl = pkg.into();
        if let Some(pkg) = self.get_package(purl.clone(), tx).await? {
            pkg.get_package_version_range(purl, start, end, tx).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageContext>, Error> {
        let purl = pkg.into();
        Ok(package::Entity::find()
            .filter(package::Column::Type.eq(purl.ty.clone()))
            .filter(package::Column::Namespace.eq(purl.namespace.clone()))
            .filter(package::Column::Name.eq(purl.name.clone()))
            .one(&self.connection(tx))
            .await?
            .map(|package| (self, package).into()))
    }
}

#[derive(Clone)]
pub struct PackageContext {
    pub(crate) system: InnerSystem,
    pub(crate) package: package::Model,
}

impl Debug for PackageContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package.fmt(f)
    }
}

impl From<(&InnerSystem, package::Model)> for PackageContext {
    fn from((system, package): (&InnerSystem, Model)) -> Self {
        Self {
            system: system.clone(),
            package,
        }
    }
}

impl PackageContext {
    pub async fn ingest_package_version_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionRangeContext, Error> {
        let purl = pkg.into();
        if let Some(found) = self.get_package_version_range(purl, start, end, tx).await? {
            Ok(found)
        } else {
            let entity = package_version_range::ActiveModel {
                id: Default::default(),
                package_id: Set(self.package.id),
                start: Set(start.to_string()),
                end: Set(end.to_string()),
            };

            Ok((self, entity.insert(&self.system.connection(tx)).await?).into())
        }
    }

    pub async fn get_package_version_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionRangeContext>, Error> {
        let purl = pkg.into();

        Ok(package_version_range::Entity::find()
            .filter(package_version_range::Column::PackageId.eq(self.package.id))
            .filter(package_version_range::Column::Start.eq(start.to_string()))
            .filter(package_version_range::Column::End.eq(end.to_string()))
            .one(&self.system.connection(tx))
            .await?
            .map(|package_version_range| (self, package_version_range).into()))
    }

    pub async fn ingest_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionContext, Error> {
        let purl = pkg.into();

        if let Some(version) = &purl.version {
            if let Some(found) = self.get_package_version(purl.clone(), tx.clone()).await? {
                return Ok(found);
            } else {
                let model = package_version::ActiveModel {
                    id: Default::default(),
                    package_id: Set(self.package.id),
                    version: Set(version.clone()),
                };

                Ok((self, model.insert(&self.system.connection(tx)).await?).into())
            }
        } else {
            Err(Error::Purl(PurlErr::MissingVersion))
        }
    }

    pub async fn get_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionContext>, Error> {
        let purl = pkg.into();
        if let Some(package_version) = package_version::Entity::find()
            .join(JoinType::Join, package_version::Relation::Package.def())
            .filter(package::Column::Id.eq(self.package.id))
            .filter(package_version::Column::Version.eq(purl.version.clone()))
            .one(&self.system.connection(tx))
            .await?
        {
            Ok(Some((self, package_version).into()))
        } else {
            Ok(None)
        }
    }

    /*
    /// Locate all SBOMs that contain this package.
    ///
    pub async fn sboms_containing(&self, tx: Transactional<'_>) -> Result<Vec<SbomContext>, Error> {
        Ok(sbom::Entity::find()
            .filter(
                sbom::Column::Id.in_subquery(
                    Query::select()
                        .column(package_dependency::Column::SbomId)
                        .cond_having(
                            Condition::any()
                                .add(
                                    package_dependency::Column::DependentPackageId
                                        .eq(self.package.id),
                                )
                                .add(
                                    package_dependency::Column::DependencyPackageId
                                        .eq(self.package.id),
                                ),
                        )
                        .group_by_columns([
                            package_dependency::Column::SbomId,
                            package_dependency::Column::DependencyPackageId,
                            package_dependency::Column::DependentPackageId,
                        ])
                        .from(package_dependency::Entity)
                        .to_owned(),
                ),
            )
            .all(&self.system.connection(tx))
            .await?
            .drain(0..)
            .map(|sbom| (&self.system, sbom).into())
            .collect())
    }

    /// Locate all SBOMs that describe this package.
    pub async fn sboms_describing(&self, tx: Transactional<'_>) -> Result<Vec<SbomContext>, Error> {
        Ok(sbom::Entity::find()
            .filter(
                sbom::Column::Id.in_subquery(
                    Query::select()
                        .column(package_dependency::Column::SbomId)
                        .cond_having(
                            Condition::any()
                                .add(
                                    sbom_describes_package::Column::PackageId
                                        .eq(self.package.id),
                                )
                        )
                        .group_by_columns([
                            sbom_describes_package::Column::SbomId,
                            sbom_describes_package::Column::PackageId,
                        ])
                        .from(package_dependency::Entity)
                        .to_owned(),
                ),
            )
            .all(&self.system.connection(tx))
            .await?
            .drain(0..)
            .map(|sbom| (&self.system, sbom).into())
            .collect())
    }

     */
}

#[derive(Clone)]
pub struct PackageVersionRangeContext {
    pub(crate) package: PackageContext,
    pub(crate) package_version_range: package_version_range::Model,
}

impl Debug for PackageVersionRangeContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version_range.fmt(f)
    }
}

impl From<(&PackageContext, package_version_range::Model)> for PackageVersionRangeContext {
    fn from(
        (package, package_version_range): (&PackageContext, package_version_range::Model),
    ) -> Self {
        Self {
            package: package.clone(),
            package_version_range,
        }
    }
}

impl PackageVersionRangeContext {}

#[derive(Clone)]
pub struct PackageVersionContext {
    pub(crate) package: PackageContext,
    pub(crate) package_version: package_version::Model,
}

impl Debug for PackageVersionContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version.fmt(f)
    }
}

impl From<(&PackageContext, package_version::Model)> for PackageVersionContext {
    fn from((package, package_version): (&PackageContext, package_version::Model)) -> Self {
        Self {
            package: package.clone(),
            package_version,
        }
    }
}

impl PackageVersionContext {
    pub async fn ingest_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        mut tx: Transactional<'_>,
    ) -> Result<QualifiedPackageContext, Error> {
        let purl = pkg.into();

        if let Some(found) = self.get_qualified_package(purl.clone(), tx.clone()).await? {
            return Ok(found);
        }

        // No appropriate qualified package, create one.
        let qualified_package = qualified_package::ActiveModel {
            id: Default::default(),
            package_version_id: Set(self.package_version.package_id),
        };

        let qualified_package = qualified_package
            .insert(&self.package.system.connection(tx))
            .await?;

        for (k, v) in &purl.qualifiers {
            let qualifier = package_qualifier::ActiveModel {
                id: Default::default(),
                qualified_package_id: Set(qualified_package.id),
                key: Set(k.clone()),
                value: Set(v.clone()),
            };

            qualifier
                .insert(&self.package.system.connection(tx))
                .await?;
        }

        Ok((self, qualified_package, purl.qualifiers.clone()).into())
    }

    pub async fn get_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<QualifiedPackageContext>, Error> {
        let purl = pkg.into();
        let found = qualified_package::Entity::find()
            .filter(qualified_package::Column::PackageVersionId.eq(self.package_version.id))
            .find_with_related(package_qualifier::Entity)
            .all(&self.package.system.connection(tx))
            .await?;

        for (qualified_package, qualifiers) in found {
            let qualifiers_map = qualifiers
                .iter()
                .map(|qualifier| (qualifier.key.clone(), qualifier.value.clone()))
                .collect::<HashMap<_, _>>();

            if purl.qualifiers == qualifiers_map {
                return Ok(Some((self, qualified_package, qualifiers_map).into()));
            }
        }

        Ok(None)
    }
}

#[derive(Clone)]
pub struct QualifiedPackageContext {
    pub(crate) package_version: PackageVersionContext,
    pub(crate) qualified_package: qualified_package::Model,
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
        qualified_package::Model,
        HashMap<String, String>,
    )> for QualifiedPackageContext
{
    fn from(
        (package_version, qualified_package, qualifiers): (
            &PackageVersionContext,
            qualified_package::Model,
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

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::system::InnerSystem;
    use huevos_common::purl::Purl;

    #[tokio::test]
    async fn ingest_packages() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_packages").await?;

        let pkg1 = system
            .ingest_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
            .await?;

        let pkg2 = system
            .ingest_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
            .await?;

        let pkg3 = system
            .ingest_package("pkg://maven/io.quarkus/quarkus-addons", Transactional::None)
            .await?;

        assert_eq!(pkg1.package.id, pkg2.package.id,);

        assert_ne!(pkg1.package.id, pkg3.package.id);

        Ok(())
    }

    #[tokio::test]
    async fn ingest_package_versions_missing_version() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_package_versions_missing_version").await?;

        let result = system
            .ingest_package_version("pkg://maven/io.quarkus/quarkus-addons", Transactional::None)
            .await;

        assert!(matches!(result, Err(_)));

        Ok(())
    }

    #[tokio::test]
    async fn ingest_package_versions() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let system = InnerSystem::for_test("ingest_package_versions").await?;

        let pkg1 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg2 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg3 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@4.5.6",
                Transactional::None,
            )
            .await?;

        assert_eq!(pkg1.package.package.id, pkg2.package.package.id);
        assert_eq!(pkg1.package_version.id, pkg2.package_version.id);

        assert_eq!(pkg1.package.package.id, pkg3.package.package.id);
        assert_ne!(pkg1.package_version.id, pkg3.package_version.id);

        Ok(())
    }

    #[tokio::test]
    async fn ingest_qualified_packages() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let system = InnerSystem::for_test("ingest_qualified_packages").await?;

        let pkg1 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg2 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg3 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar",
                Transactional::None,
            )
            .await?;

        let pkg4 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar",
                Transactional::None,
            )
            .await?;

        assert_eq!(pkg1.qualified_package.id, pkg2.qualified_package.id);
        assert_eq!(pkg3.qualified_package.id, pkg4.qualified_package.id);

        assert_ne!(pkg1.qualified_package.id, pkg3.qualified_package.id);

        assert_eq!(
            "pkg://maven/io.quarkus/quarkus-core@1.2.3",
            Purl::from(pkg1).to_string().as_str()
        );
        assert_eq!(
            "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar",
            Purl::from(pkg3).to_string().as_str()
        );

        Ok(())
    }

    #[tokio::test]
    async fn ingest_package_version_ranges() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let system = InnerSystem::for_test("ingest_package_version_ranges").await?;

        let range1 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.0",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let range2 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.0",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let range3 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-addons",
                "1.0.0",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        assert_eq!(
            range1.package_version_range.id,
            range2.package_version_range.id
        );
        assert_ne!(
            range1.package_version_range.id,
            range3.package_version_range.id
        );

        Ok(())
    }

    /*

    #[tokio::test]
    async fn ingest_package_dependencies() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_package_dependencies").await?;

        let sbom = system
            .ingest_sbom("http://test.sbom/ingest_package_dependencies.json", "7")
            .await?;

        /*
        let result = system
            .ingest_package_dependency(
                "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
                "pkg:maven/io.quarkus/quarkus-jdbc-base@1.13.5.Final?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        let result = system
            .ingest_package_dependency(
                "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
                "pkg:maven/io.quarkus/quarkus-postgres@1.13.5.Final?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        let result = system
            .direct_dependencies(
                "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
                Transactional::None,
            )
            .await?;

        println!("{:?}", result);
         */
        Ok(())
    }

    #[tokio::test]
    async fn transitive_dependencies() -> Result<(), anyhow::Error> {
        env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .init();


        let system = InnerSystem::for_test("transitive_dependencies").await?;

        let sbom = system
            .ingest_sbom("http://test.sbom/transitive_dependencies.json", "8")
            .await?;

        println!("{:#?}", sbom);

        system
            .ingest_package_dependency(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                "pkg:maven/com.test/package-ab@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        system
            .ingest_package_dependency(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        system
            .ingest_package_dependency(
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                "pkg:maven/com.test/package-acd@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        system
            .ingest_package_dependency(
                "pkg:maven/com.test/package-ab@1.0?type=jar",
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        let result = system
            .transitive_package_dependencies(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                Transactional::None,
            )
            .await?;

        assert_eq!(
            Purl::from("pkg:maven/com.test/package-a@1.0?type=jar"),
            result.purl
        );
        assert_eq!(2, result.dependencies.len());

        Ok(())
    }
         */
}

/*
pub(crate) fn packages_to_purls(
    packages: Vec<(
        huevos_entity::package::Model,
        Vec<huevos_entity::package_qualifier::Model>,
    )>,
) -> Result<Vec<Purl>, anyhow::Error> {
    let mut purls = Vec::new();

    for (base, qualifiers) in &packages {
        purls.push(package_to_purl(base.clone(), qualifiers.clone())?);
    }

    Ok(purls)
}

 */

/*
pub(crate) fn package_to_purl(
    base: huevos_entity::package::Model,
    qualifiers: Vec<huevos_entity::package_qualifier::Model>,
) -> Result<Purl, anyhow::Error> {
    let mut purl = PackageUrl::new(base.package_type.clone(), base.package_name.clone())?;

    //purl.with_version(base.version.clone());

    if let Some(namespace) = &base.package_namespace {
        purl.with_namespace(namespace.clone());
    }

    for qualifier in qualifiers {
        purl.add_qualifier(qualifier.key.clone(), qualifier.value.clone())?;
    }

    Ok(purl.into())
}


 */
