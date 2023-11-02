use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, EntityOrSelect,
    EntityTrait, ModelTrait, QueryFilter, QuerySelect, Set, Statement, Value,
};

use huevos_entity::package::{PackageNamespace, PackageType};
use huevos_entity::package_dependency::ToDependency;
use huevos_entity::{package, package_dependency, package_qualifier};

use crate::{PackageTree, Purl};

pub struct PackageSystem {
    pub(crate) db: Arc<DatabaseConnection>,
}

impl PackageSystem {
    pub async fn ingest_package<'p, P: Into<Purl<'p>>>(
        &self,
        pkg: P,
    ) -> Result<package::Model, anyhow::Error> {
        //let purl = PackageUrl::from_str(pkg)?;
        let purl = pkg.into().package_url;

        let pkg = self
            .insert_or_fetch_package(
                purl.ty(),
                purl.namespace(),
                purl.name(),
                purl.version().unwrap(),
                purl.qualifiers(),
            )
            .await?;

        Ok(pkg)
    }

    pub async fn packages(&self) -> Result<Vec<Purl<'_>>, anyhow::Error> {
        let found = package::Entity::find()
            .find_with_related(package_qualifier::Entity)
            .all(&*self.db)
            .await?;

        Ok(self.packages_to_purls(found).await?)
    }

    pub async fn insert_or_fetch_package<'a>(
        &self,
        r#type: &str,
        namespace: Option<&str>,
        name: &str,
        version: &str,
        qualifiers: &HashMap<Cow<'a, str>, Cow<'a, str>>,
    ) -> Result<package::Model, anyhow::Error> {
        log::info!("insert or fetch pkg");

        let fetch = self
            .get_package(&r#type, &namespace, &name, version, qualifiers)
            .await?;
        if let Some(pkg) = fetch {
            Ok(pkg)
        } else {
            let mut entity = package::ActiveModel {
                package_type: Set(r#type.to_string()),
                package_name: Set(name.to_string()),
                version: Set(version.to_owned()),
                ..Default::default()
            };

            if let Some(ns) = namespace {
                entity.package_namespace = Set(Some(ns.to_string()))
            }

            let inserted = entity.insert(&*self.db).await?;

            for (k, v) in qualifiers {
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

    async fn get_package<'a>(
        &self,
        r#type: &str,
        namespace: &Option<&str>,
        name: &str,
        version: &str,
        qualifiers: &HashMap<Cow<'a, str>, Cow<'a, str>>,
    ) -> Result<Option<package::Model>, anyhow::Error> {
        let mut conditions = Condition::all()
            .add(package::Column::PackageType.eq(r#type.to_string()))
            .add(package::Column::PackageName.eq(name.to_string()))
            .add(package::Column::Version.eq(version));

        if let Some(ns) = namespace {
            conditions = conditions.add(package::Column::PackageNamespace.eq(ns.to_string()));
        } else {
            conditions = conditions.add(package::Column::PackageNamespace.is_null());
        }

        let found = package::Entity::find()
            .find_with_related(package_qualifier::Entity)
            .filter(conditions)
            .all(&*self.db)
            .await?;

        if found.is_empty() {
            return Ok(None);
        } else {
            for (found_package, found_qualifiers) in found {
                if qualifiers.is_empty() && found_qualifiers.is_empty() {
                    return Ok(Some(found_package));
                }

                if qualifiers.len() != found_qualifiers.len() {
                    return Ok(None);
                }

                for (expected_k, expected_v) in qualifiers {
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

    pub async fn ingest_package_dependency<'p1, 'p2, P1: Into<Purl<'p1>>, P2: Into<Purl<'p2>>>(
        &self,
        dependent_package: P1,
        dependency_package: P2,
    ) -> Result<package_dependency::Model, anyhow::Error> {
        let dependent = self.ingest_package(dependent_package).await?;

        let dependency = self.ingest_package(dependency_package).await?;

        let entity = package_dependency::ActiveModel {
            dependent_package_id: Set(dependent.id),
            dependency_package_id: Set(dependency.id),
        };

        Ok(entity.insert(&*self.db).await?)
    }

    async fn packages_to_purls(
        &self,
        packages: Vec<(package::Model, Vec<package_qualifier::Model>)>,
    ) -> Result<Vec<Purl<'_>>, anyhow::Error> {
        let mut purls = Vec::new();

        for (base, qualifiers) in packages {
            let mut purl = PackageUrl::new(base.package_type, base.package_name)?;

            purl.with_version(base.version);

            if let Some(namespace) = base.package_namespace {
                purl.with_namespace(namespace);
            }

            for qualifier in qualifiers {
                purl.add_qualifier(qualifier.key, qualifier.value)?;
            }

            purls.push(purl.into());
        }

        Ok(purls)
    }

    pub async fn direct_dependencies<'p, P: Into<Purl<'p>>>(
        &self,
        dependent_package: P,
    ) -> Result<Vec<Purl>, anyhow::Error> {
        let dependent = self.ingest_package(dependent_package).await?;

        let found = dependent
            .find_linked(ToDependency)
            .find_with_related(package_qualifier::Entity)
            .all(&*self.db)
            .await?;

        Ok(self.packages_to_purls(found).await?)
    }

    pub async fn transitive_dependencies<'p, P: Into<Purl<'p>>>(
        &'p self,
        root: P,
    ) -> Result<PackageTree<'p>, anyhow::Error> {
        let root_purl = root.into();

        let mut purls = HashMap::new();
        let mut queue = Vec::new();
        queue.push(root_purl.clone());

        while let Some(cur) = queue.pop() {
            let dependencies = self.direct_dependencies(cur.clone()).await?;
            queue.extend_from_slice(&dependencies);
            purls.insert(cur, dependencies);
        }

        fn build_tree<'p>(
            root: &Purl<'p>,
            map: &HashMap<Purl<'p>, Vec<Purl<'p>>>,
        ) -> PackageTree<'p> {
            let dependencies = map
                .get(&root)
                .iter()
                .flat_map(|deps| deps.iter().map(|dep| build_tree(dep, map)))
                .collect();

            PackageTree {
                purl: root.clone(),
                dependencies,
            }
        }

        Ok(build_tree(&root_purl, &purls))

        /*
        Ok( PackageTree {
            purl: root_purl.clone(),
            dependencies: vec![],
        })

             */
    }

    /*
    pub async fn transitive_dependencies<'p, P: Into<Purl<'p>>>(
        &'p self,
        root: P,
    ) -> Result<PackageTree<'p>, anyhow::Error> {

        let root_model = self.ingest_package( root).await?;
        let root_id = Value::Int(Some(root_model.id));

        let result = package_dependency::Entity::find()
            .from_raw_sql(
                Statement::from_sql_and_values(
                    self.db.get_database_backend(),
                    r#"
                    WITH RECURSIVE transitive AS (
                        SELECT
                            timestamp, dependent_package_id, dependency_package_id
                        FROM
                            package_dependency
                        WHERE
                            dependent_package_id = $1
                        UNION
                        SELECT
                            pd.timestamp, pd.dependent_package_id, pd.dependency_package_id
                        FROM
                            package_dependency pd
                        INNER JOIN transitive transitive1
                            ON pd.dependent_package_id = transitive1.dependency_package_id
                    ) SELECT * FROM transitive
                    "#,
                        vec![root_id]
                )
            )
            .all(&*self.db)
            .await?;

        println!("{:#?}", result);

        todo!()
    }

     */
}

#[cfg(test)]
mod tests {
    use crate::Purl;
    use std::collections::HashSet;

    use crate::system::System;

    #[tokio::test]
    async fn ingest_packages() -> Result<(), anyhow::Error> {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

        let system = System::start().await?.package();

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
            system.ingest_package(pkg).await?;
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
        let system = System::start().await?.package();

        let result = system
            .ingest_package_dependency(
                "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
                "pkg:maven/io.quarkus/quarkus-jdbc-base@1.13.5.Final?type=jar",
            )
            .await?;

        let result = system
            .ingest_package_dependency(
                "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
                "pkg:maven/io.quarkus/quarkus-postgres@1.13.5.Final?type=jar",
            )
            .await?;

        let result = system
            .direct_dependencies(
                "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
            )
            .await?;

        println!("{:?}", result);
        Ok(())
    }

    #[tokio::test]
    async fn transitive_dependencies() -> Result<(), anyhow::Error> {
        let system = System::start().await?.package();

        system
            .ingest_package_dependency(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                "pkg:maven/com.test/package-ab@1.0?type=jar",
            )
            .await?;

        system
            .ingest_package_dependency(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                "pkg:maven/com.test/package-ac@1.0?type=jar",
            )
            .await?;

        system
            .ingest_package_dependency(
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                "pkg:maven/com.test/package-acd@1.0?type=jar",
            )
            .await?;

        let result = system
            .transitive_dependencies("pkg:maven/com.test/package-a@1.0?type=jar")
            .await?;

        assert_eq!(
            Purl::from("pkg:maven/com.test/package-a@1.0?type=jar"),
            result.purl
        );
        assert_eq!(2, result.dependencies.len());

        Ok(())
    }
}
