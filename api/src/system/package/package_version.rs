use std::fmt::{Debug, Formatter};
use huevos_common::purl::Purl;
use sea_orm::{ActiveModelTrait, EntityTrait, ColumnTrait,Set, QueryFilter};
use huevos_entity as entity;
use std::collections::HashMap;
use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::package::PackageContext;
use crate::system::package::qualified_package::QualifiedPackageContext;

#[derive(Clone)]
pub struct PackageVersionContext {
    pub(crate) package: PackageContext,
    pub(crate) package_version: entity::package_version::Model,
}

impl Debug for PackageVersionContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version.fmt(f)
    }
}

impl From<(&PackageContext, entity::package_version::Model)> for PackageVersionContext {
    fn from((package, package_version): (&PackageContext, entity::package_version::Model)) -> Self {
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
        let qualified_package = entity::qualified_package::ActiveModel {
            id: Default::default(),
            package_version_id: Set(self.package_version.package_id),
        };

        let qualified_package = qualified_package
            .insert(&self.package.system.connection(tx))
            .await?;

        for (k, v) in &purl.qualifiers {
            let qualifier = entity::package_qualifier::ActiveModel {
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
        let found = entity::qualified_package::Entity::find()
            .filter(entity::qualified_package::Column::PackageVersionId.eq(self.package_version.id))
            .find_with_related(entity::package_qualifier::Entity)
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
