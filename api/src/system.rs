use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;

use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, Database, DatabaseConnection,
    EntityTrait, ModelTrait, QueryFilter, Set, Statement,
};
use sea_orm_migration::MigratorTrait;

use huevos_entity::{package, package_name, package_namespace, package_qualifier, package_type};
use migration::Migrator;

const DB_URL: &str = "postgres://postgres:eggs@localhost";
const DB_NAME: &str = "huevos";

pub struct System {
    db: DatabaseConnection,
}

impl System {
    pub(crate) async fn start() -> Result<Self, anyhow::Error> {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .init();

        let db: DatabaseConnection = Database::connect(DB_URL).await?;
        //let schema_manager = SchemaManager::new(db);
        //schema_manager.ref

        db.execute(Statement::from_string(
            db.get_database_backend(),
            format!("DROP DATABASE IF EXISTS \"{}\";", DB_NAME),
        ))
        .await?;
        db.execute(Statement::from_string(
            db.get_database_backend(),
            format!("CREATE DATABASE \"{}\";", DB_NAME),
        ))
        .await?;

        Migrator::refresh(&db).await?;

        Ok(Self { db })
    }

    pub async fn ingest_package(&self, pkg: &str) -> Result<(), anyhow::Error> {
        let purl = PackageUrl::from_str(pkg)?;

        let r#type = self.insert_or_fetch_package_type(purl.ty()).await?;
        let namespace = self
            .insert_or_fetch_package_namespace(purl.namespace())
            .await?;
        let name = self.insert_or_fetch_package_name(purl.name()).await?;

        let pkg = self
            .insert_or_fetch_package(
                r#type,
                namespace,
                name,
                purl.version().unwrap(),
                purl.qualifiers(),
            )
            .await?;

        Ok(())
    }

    //pub async fn packages(&self) -> Result<Vec<package::Model>, anyhow::Error> {
        //Ok(package::Entity::find().all(&self.db).await?)
    //}

    pub async fn packages(&self) -> Result<Vec<PackageUrl>, anyhow::Error> {
        let found = package::Entity::find()
            .find_with_related(package_qualifier::Entity)
            .all(&self.db).await?;

        let mut purls = Vec::new();

        for (base, qualifiers) in found {

            let r#type = package_type::Entity::find_by_id(
                base.package_type_id
            ).one(&self.db).await?;

            let name = package_name::Entity::find_by_id(
                base.package_name_id
            ).one(&self.db).await?;

            if let (Some(r#type), Some(name)) = (r#type, name) {
                let mut purl = PackageUrl::new(
                    r#type.r#type,
                    name.name,
                )?;

                purl.with_version(
                    base.version
                );

                if let Some(ns_id) = base.package_namespace_id {
                    if let Some(ns) = package_namespace::Entity::find_by_id(ns_id).one(&self.db).await? {
                        purl.with_namespace(
                            ns.namespace
                        );
                    }
                }

                for qualifier in qualifiers {
                    purl.add_qualifier(
                        qualifier.key,
                        qualifier.value
                    )?;
                }

                purls.push(purl);
            }
        }

        Ok(purls)
    }

    pub async fn insert_or_fetch_package<'a>(
        &self,
        r#type: package_type::Model,
        namespace: Option<package_namespace::Model>,
        name: package_name::Model,
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
                package_type_id: Set(r#type.id),
                package_name_id: Set(name.id),
                version: Set(version.to_owned()),
                ..Default::default()
            };

            if let Some(ns) = namespace {
                entity.package_namespace_id = Set(Some(ns.id))
            }

            let inserted = entity.insert(&self.db).await?;

            for (k, v) in qualifiers {
                let entity = package_qualifier::ActiveModel {
                    package_id: Set( inserted.id),
                    key: Set( k.to_string() ),
                    value: Set( v.to_string() ),
                    ..Default::default()
                };
                entity.insert(&self.db).await?;
            }

            Ok(inserted)
        }
    }

    async fn get_package<'a>(
        &self,
        r#type: &package_type::Model,
        namespace: &Option<package_namespace::Model>,
        name: &package_name::Model,
        version: &str,
        qualifiers: &HashMap<Cow<'a, str>, Cow<'a, str>>,
    ) -> Result<Option<package::Model>, anyhow::Error> {
        let mut conditions = Condition::all()
            .add(package::Column::PackageTypeId.eq(r#type.id))
            .add(package::Column::PackageNameId.eq(name.id))
            .add(package::Column::Version.eq(version));

        if let Some(ns) = namespace {
            conditions = conditions.add(package::Column::PackageNamespaceId.eq(ns.id));
        }

        let found = package::Entity::find()
            .find_with_related(package_qualifier::Entity)
            .filter(conditions)
            .all(&self.db)
            .await?;

        if found.is_empty() {
            return Ok(None)
        } else {
            for (found_package, found_qualifiers) in found {
                if qualifiers.is_empty() && found_qualifiers.is_empty() {
                    return Ok(Some(found_package))
                }

                if qualifiers.len() != found_qualifiers.len() {
                    return Ok(None)
                }

                for (expected_k, expected_v) in qualifiers {
                    if found_qualifiers.iter().any(|found_q| {
                        found_q.key == *expected_k && found_q.value == *expected_v
                    }) {
                        return Ok(Some(found_package))
                    }
                }
            }
        }

        Ok(None)
    }

    pub async fn get_package_type(
        &self,
        r#type: &str,
    ) -> Result<Option<package_type::Model>, anyhow::Error> {
        Ok(package_type::Entity::find()
            .filter(Condition::all().add(package_type::Column::Type.eq(r#type)))
            .all(&self.db)
            .await?
            .get(0)
            .cloned())
    }

    pub async fn insert_or_fetch_package_type(
        &self,
        r#type: &str,
    ) -> Result<package_type::Model, anyhow::Error> {
        log::info!("insert or fetch pkg-type {}", r#type);
        let fetch = self.get_package_type(r#type).await?;
        if let Some(r#type) = fetch {
            Ok(r#type)
        } else {
            let entity = package_type::ActiveModel {
                r#type: Set(r#type.to_owned()),
                ..Default::default()
            };

            Ok(entity.insert(&self.db).await?)
        }
    }

    pub async fn package_types(&self) -> Result<Vec<package_type::Model>, anyhow::Error> {
        Ok(package_type::Entity::find().all(&self.db).await?)
    }

    pub async fn fetch_package_namespace(
        &self,
        namespace: &str,
    ) -> Result<Option<package_namespace::Model>, anyhow::Error> {
        log::info!("insert or fetch pkg-ns {}", namespace);
        Ok(package_namespace::Entity::find()
            .filter(Condition::all().add(package_namespace::Column::Namespace.eq(namespace)))
            .all(&self.db)
            .await?
            .get(0)
            .cloned())
    }
    pub async fn insert_or_fetch_package_namespace(
        &self,
        namespace: Option<&str>,
    ) -> Result<Option<package_namespace::Model>, anyhow::Error> {
        if let Some(namespace) = namespace {
            let fetch = self.fetch_package_namespace(namespace).await?;
            if fetch.is_some() {
                Ok(fetch)
            } else {
                let entity = package_namespace::ActiveModel {
                    namespace: Set(namespace.to_owned()),
                    ..Default::default()
                };

                Ok(Some(entity.insert(&self.db).await?))
            }
        } else {
            Ok(None)
        }
    }

    pub async fn package_namespaces(&self) -> Result<Vec<package_namespace::Model>, anyhow::Error> {
        Ok(package_namespace::Entity::find().all(&self.db).await?)
    }

    pub async fn get_package_name(
        &self,
        name: &str,
    ) -> Result<Option<package_name::Model>, anyhow::Error> {
        Ok(package_name::Entity::find()
            .filter(Condition::all().add(package_name::Column::Name.eq(name)))
            .all(&self.db)
            .await?
            .get(0)
            .cloned())
    }

    pub async fn insert_or_fetch_package_name(
        &self,
        name: &str,
    ) -> Result<package_name::Model, anyhow::Error> {
        log::info!("insert or fetch pkg-name {}", name);
        let fetch = self.get_package_name(name).await?;
        if let Some(name) = fetch {
            Ok(name)
        } else {
            let entity = package_name::ActiveModel {
                name: Set(name.to_owned()),
                ..Default::default()
            };

            Ok(entity.insert(&self.db).await?)
        }
    }

    pub async fn package_names(&self) -> Result<Vec<package_name::Model>, anyhow::Error> {
        Ok(package_name::Entity::find().all(&self.db).await?)
    }
}
