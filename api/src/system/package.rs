use std::collections::{HashMap, HashSet};

use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, FromQueryResult,
    ModelTrait, NotSet, QueryFilter, QuerySelect, Set, Statement,
};
use sea_query::Value;

use huevos_common::purl::{Purl, PurlErr};
use huevos_entity::package::{PackageNamespace, PackageType};
use huevos_entity::package_dependency::{ToDependency, ToDependent};
use huevos_entity::{package, package_dependency, package_qualifier, sbom};

use crate::db::{ConnectionOrTransaction, Transactional};
use crate::system::error::Error;
use crate::system::System;
use huevos_common::package::PackageTree;

impl System {
    pub async fn ingest_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<package::Model, Error> {
        let purl = pkg.into();

        if let Some(version) = &purl.version {
            let pkg = self.insert_or_fetch_package(purl, tx).await?;
            Ok(pkg)
        } else {
            Err(PurlErr::MissingVersion.into())
        }
    }

    pub async fn fetch_package<'p, P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<package::Model>, Error> {
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
            .all(&*self.db)
            .await?;

        Ok(self.packages_to_purls(found)?)
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
            .all(&*self.db)
            .await?;

        Ok(self.packages_to_purls(found)?)
    }

    pub async fn insert_or_fetch_package<P: Into<Purl>>(
        &self,
        purl: P,
        tx: Transactional<'_>,
    ) -> Result<package::Model, anyhow::Error> {
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

            let inserted = entity.insert(&*self.db).await?;

            for (k, v) in &purl.qualifiers {
                let entity = package_qualifier::ActiveModel {
                    package_id: Set(inserted.id),
                    key: Set(k.to_string()),
                    value: Set(v.to_string()),
                    ..Default::default()
                };
                entity.insert(&*self.db).await?;
            }

            Ok(inserted)
        }
    }

    fn default_tx(&self) -> &dyn ConnectionTrait {
        &*self.db
    }

    async fn get_package<P: Into<Purl>>(
        &self,
        purl: P,
        tx: Transactional<'_>,
    ) -> Result<Option<package::Model>, Error> {
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
                    return Ok(Some(found_package));
                }

                if purl.qualifiers.len() != found_qualifiers.len() {
                    return Ok(None);
                }

                for (expected_k, expected_v) in &purl.qualifiers {
                    if found_qualifiers
                        .iter()
                        .any(|found_q| found_q.key == *expected_k && found_q.value == *expected_v)
                    {
                        return Ok(Some(found_package));
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
            .all(&*self.db)
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
            .all(&*self.db)
            .await?
            .iter()
            .map(|e| e.package_namespace.clone())
            .collect())
    }

    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------

    pub async fn ingest_package_dependency<P1: Into<Purl>, P2: Into<Purl>>(
        &self,
        dependent_package: P1,
        dependency_package: P2,
        sbom: &sbom::Model,
        tx: Transactional<'_>,
    ) -> Result<package_dependency::Model, anyhow::Error> {
        let dependent = self.ingest_package(dependent_package, tx.clone()).await?;
        let dependency = self.ingest_package(dependency_package, tx.clone()).await?;

        match package_dependency::Entity::find()
            .filter(
                Condition::all()
                    .add(package_dependency::Column::DependentPackageId.eq(dependent.id))
                    .add(package_dependency::Column::DependencyPackageId.eq(dependency.id))
                    .add(package_dependency::Column::SbomId.eq(sbom.id)),
            )
            .one(&*self.db)
            .await?
        {
            None => {
                let entity = package_dependency::ActiveModel {
                    dependent_package_id: Set(dependent.id),
                    dependency_package_id: Set(dependency.id),
                    sbom_id: Set(sbom.id),
                };

                Ok(entity.insert(&*self.db).await?)
            }
            Some(found) => Ok(found),
        }
    }

    pub(crate) fn packages_to_purls(
        &self,
        packages: Vec<(package::Model, Vec<package_qualifier::Model>)>,
    ) -> Result<Vec<Purl>, anyhow::Error> {
        let mut purls = Vec::new();

        for (base, qualifiers) in &packages {
            purls.push(self.package_to_purl(base.clone(), qualifiers.clone())?);
        }

        Ok(purls)
    }

    fn package_to_purl(
        &self,
        base: package::Model,
        qualifiers: Vec<package_qualifier::Model>,
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

    pub async fn direct_dependencies<P: Into<Purl>>(
        &self,
        dependent_package: P,
        tx: Transactional<'_>,
    ) -> Result<Vec<Purl>, Error> {
        let dependent = self.ingest_package(dependent_package, tx).await?;

        let found = dependent
            .find_linked(ToDependency)
            .find_with_related(package_qualifier::Entity)
            .all(&*self.db)
            .await?;

        Ok(self.packages_to_purls(found)?)
    }

    pub async fn direct_package_dependencies<'p, P: Into<Purl>>(
        &self,
        dependency_package: P,
        tx: Transactional<'_>,
    ) -> Result<Vec<Purl>, Error> {
        let dependency = self.ingest_package(dependency_package, tx).await?;

        let found = dependency
            .find_linked(ToDependent)
            .find_with_related(package_qualifier::Entity)
            .all(&*self.db)
            .await?;

        Ok(self.packages_to_purls(found)?)
    }

    pub async fn transitive_package_dependencies<P: Into<Purl>>(
        &self,
        root: P,
        tx: Transactional<'_>,
    ) -> Result<PackageTree, Error> {
        let root_model = self.ingest_package(root, tx).await?;
        let root_id = Value::Int(Some(root_model.id));

        let relationships = package_dependency::Entity::find()
            .from_raw_sql(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                r#"
                    WITH RECURSIVE transitive AS (
                        SELECT
                            timestamp, dependent_package_id, dependency_package_id, sbom_id
                        FROM
                            package_dependency
                        WHERE
                            dependent_package_id = $1
                        UNION
                        SELECT
                            pd.timestamp, pd.dependent_package_id, pd.dependency_package_id, pd.sbom_id
                        FROM
                            package_dependency pd
                        INNER JOIN transitive transitive1
                            ON pd.dependent_package_id = transitive1.dependency_package_id
                    )
                    SELECT * FROM transitive
                    "#,
                vec![root_id],
            ))
            .all(&*self.db)
            .await?;

        let mut dependencies = HashMap::new();
        let mut all_packages = HashSet::new();

        for relationship in relationships {
            all_packages.insert(relationship.dependent_package_id);
            all_packages.insert(relationship.dependency_package_id);
            dependencies
                .entry(relationship.dependent_package_id)
                .or_insert(Vec::new())
                .push(relationship.dependency_package_id)
        }

        let mut purls = HashMap::new();

        for pkg_id in all_packages {
            let pkg = package::Entity::find_by_id(pkg_id)
                .find_with_related(package_qualifier::Entity)
                .all(&*self.db)
                .await?;

            if !pkg.is_empty() {
                let (base, qualifiers) = &pkg[0];
                let purl = self.package_to_purl(base.clone(), qualifiers.clone())?;
                purls.insert(pkg_id, purl);
            }
        }

        fn build_tree(
            root: i32,
            relationships: &HashMap<i32, Vec<i32>>,
            purls: &HashMap<i32, Purl>,
        ) -> PackageTree {
            let dependencies = relationships
                .get(&root)
                .iter()
                .flat_map(|deps| {
                    deps.iter()
                        .map(|dep| build_tree(*dep, relationships, purls))
                })
                .collect();

            PackageTree {
                id: root,
                purl: purls[&root].clone(),
                dependencies,
            }
        }

        Ok(build_tree(root_model.id, &dependencies, &purls))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::db::Transactional;
    use huevos_common::purl::Purl;

    use crate::system::System;

    #[tokio::test]
    async fn ingest_packages() -> Result<(), anyhow::Error> {
        let system = System::for_test("ingest_packages").await?;

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
        let system = System::for_test("ingest_package_dependencies").await?;

        let sbom = system
            .ingest_sbom("http://test.sbom/ingest_package_dependencies.json", "7")
            .await?;

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
        Ok(())
    }

    #[tokio::test]
    async fn transitive_dependencies() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .init();

         */

        let system = System::for_test("transitive_dependencies").await?;

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
}
