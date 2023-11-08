use huevos_common::purl::{Purl, PurlErr};
use huevos_entity::package::{Model, PackageNamespace, PackageType};
use huevos_entity::{package, package_dependency, package_qualifier, sbom, sbom_describes_package};
use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, FromQueryResult,
    ModelTrait, QueryFilter, QuerySelect, Select, Set,
};
use sea_query::Query;
use std::fmt::{Debug, Formatter};
use huevos_common::sbom::SbomLocator;

use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::sbom::SbomContext;
use crate::system::InnerSystem;

impl InnerSystem {
    pub async fn ingest_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<PackageContext, Error> {
        let purl = pkg.into();

        if let Some(version) = &purl.version {
            Ok(self.insert_or_fetch_package(purl, tx).await?)
        } else {
            Err(PurlErr::MissingVersion.into())
        }
    }

    pub async fn fetch_package<'p, P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageContext>, Error> {
        let purl = pkg.into();
        if let Some(version) = &purl.version {
            self.get_package(purl, tx).await
        } else {
            Err(PurlErr::MissingVersion.into())
        }
    }

    pub async fn packages(&self) -> Result<Vec<Purl>, Error> {
        let found = package::Entity::find()
            .find_with_related(package_qualifier::Entity)
            .all(&self.db)
            .await?;

        Ok(packages_to_purls(found)?)
    }

    pub async fn package_variants<P: Into<Purl>>(&self, purl: P) -> Result<Vec<Purl>, Error> {
        let purl = purl.into();

        let mut conditions = Condition::all()
            .add(package::Column::PackageType.eq(purl.ty.clone()))
            .add(package::Column::PackageName.eq(purl.name.clone()));

        if let Some(ns) = &purl.namespace {
            conditions = conditions.add(package::Column::PackageNamespace.eq(ns.clone()));
        }

        let found = package::Entity::find()
            .find_with_related(package_qualifier::Entity)
            .filter(conditions)
            .all(&self.db)
            .await?;

        Ok(packages_to_purls(found)?)
    }

    pub async fn insert_or_fetch_package<P: Into<Purl>>(
        &self,
        purl: P,
        tx: Transactional<'_>,
    ) -> Result<PackageContext, anyhow::Error> {
        let purl = purl.into();
        let fetch = self.get_package(purl.clone(), tx).await?;
        if let Some(pkg) = fetch {
            Ok(pkg)
        } else {
            let mut entity = package::ActiveModel {
                package_type: Set(purl.ty.to_string()),
                package_namespace: Set(purl.namespace),
                package_name: Set(purl.name.to_string()),
                version: Set(purl.version.unwrap_or_default()),
                ..Default::default()
            };

            let inserted = entity.insert(&self.db).await?;

            for (k, v) in &purl.qualifiers {
                let entity = package_qualifier::ActiveModel {
                    package_id: Set(inserted.id),
                    key: Set(k.to_string()),
                    value: Set(v.to_string()),
                    ..Default::default()
                };
                entity.insert(&self.db).await?;
            }

            Ok((self, inserted).into())
        }
    }

    async fn get_package<P: Into<Purl>>(
        &self,
        purl: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageContext>, Error> {
        let purl = purl.into();
        let mut conditions = Condition::all()
            .add(package::Column::PackageType.eq(purl.ty.to_string()))
            .add(package::Column::PackageName.eq(purl.name.to_string()))
            .add(package::Column::Version.eq(purl.version));

        if let Some(ns) = purl.namespace {
            conditions = conditions.add(package::Column::PackageNamespace.eq(ns.to_string()));
        } else {
            conditions = conditions.add(package::Column::PackageNamespace.is_null());
        }

        let found = package::Entity::find()
            .find_with_related(package_qualifier::Entity)
            .filter(conditions)
            .all(&self.connection(tx))
            .await?;

        if found.is_empty() {
            return Ok(None);
        } else {
            for (found_package, found_qualifiers) in found {
                if purl.qualifiers.is_empty() && found_qualifiers.is_empty() {
                    return Ok(Some((self, found_package).into()));
                }

                if purl.qualifiers.len() != found_qualifiers.len() {
                    return Ok(None);
                }

                for (expected_k, expected_v) in &purl.qualifiers {
                    if found_qualifiers
                        .iter()
                        .any(|found_q| found_q.key == *expected_k && found_q.value == *expected_v)
                    {
                        return Ok(Some((self, found_package).into()));
                    }
                }
            }
        }

        Ok(None)
    }

    pub async fn package_types(&self) -> Result<Vec<String>, anyhow::Error> {
        Ok(package::Entity::find()
            .select_only()
            .column(package::Column::PackageType)
            .group_by(package::Column::PackageType)
            .into_model::<PackageType>()
            .all(&self.db)
            .await?
            .iter()
            .map(|e| e.package_type.clone())
            .collect())
    }

    pub async fn package_namespaces(&self) -> Result<Vec<String>, anyhow::Error> {
        Ok(package::Entity::find()
            .select_only()
            .column(package::Column::PackageNamespace)
            .group_by(package::Column::PackageNamespace)
            .into_model::<PackageNamespace>()
            .all(&self.db)
            .await?
            .iter()
            .map(|e| e.package_namespace.clone())
            .collect())
    }

    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
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

    /// Locate all SBOMs that contain this package.
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
}

#[cfg(test)]
mod tests {
    /*
    #[tokio::test]
    async fn ingest_packages() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_packages").await?;

        let mut packages = vec![
            "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar",
            "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar",
            "pkg:maven/jakarta.el/jakarta.el-api@3.0.3?type=jar",
            "pkg:maven/org.postgresql/postgresql@42.5.0?type=jar",
            "pkg:maven/io.quarkus/quarkus-narayana-jta@2.13.5.Final?type=jar",
            "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5?type=jar",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar",
            "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
            "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar",
            "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar",
            "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=war",
            "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar&cheese=cheddar",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.3",
        ];

        for pkg in &packages {
            system.ingest_package(pkg, Transactional::None).await?;
        }

        let package_types = system.package_types().await?;

        let package_namespaces = system.package_namespaces().await?;

        let fetched_packages = system.packages().await?;

        let packages: HashSet<_> = packages.drain(..).collect();

        assert_eq!(fetched_packages.len(), packages.len());

        //for pkg in fetched_packages {
        //println!("{}", pkg.to_string());
        //}

        Ok(())
    }

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

pub(crate) fn package_to_purl(
    base: huevos_entity::package::Model,
    qualifiers: Vec<huevos_entity::package_qualifier::Model>,
) -> Result<Purl, anyhow::Error> {
    let mut purl = PackageUrl::new(base.package_type.clone(), base.package_name.clone())?;

    purl.with_version(base.version.clone());

    if let Some(namespace) = &base.package_namespace {
        purl.with_namespace(namespace.clone());
    }

    for qualifier in qualifiers {
        purl.add_qualifier(qualifier.key.clone(), qualifier.value.clone())?;
    }

    Ok(purl.into())
}
