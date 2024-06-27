use crate::package::model::details::package::PackageDetails;
use crate::package::model::details::package_version::PackageVersionDetails;
use crate::package::model::details::qualified_package::QualifiedPackageDetails;
use crate::package::model::summary::package::PackageSummary;
use crate::package::model::summary::qualified_package::QualifiedPackageSummary;
use crate::package::model::summary::r#type::TypeSummary;
use crate::Error;
use sea_orm::prelude::Uuid;
use sea_orm::{
    ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder, QuerySelect, QueryTrait,
};
use sea_query::{Condition, Order};
use trustify_common::db::limiter::LimiterTrait;
use trustify_common::db::query::{Filtering, Query};
use trustify_common::db::{Database, Transactional};
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_entity::{package, package_version, qualified_package};

pub struct PackageService {
    db: Database,
}

impl PackageService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn purl_types<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<TypeSummary>, Error> {
        #[derive(FromQueryResult)]
        struct Ecosystem {
            r#type: String,
        }

        let connection = self.db.connection(&tx);

        let ecosystems: Vec<_> = package::Entity::find()
            .select_only()
            .column(package::Column::Type)
            .group_by(package::Column::Type)
            .distinct()
            .order_by(package::Column::Type, Order::Asc)
            .into_model::<Ecosystem>()
            .all(&connection)
            .await?
            .into_iter()
            .map(|e| e.r#type)
            .collect();

        TypeSummary::from_names(&ecosystems, &connection).await
    }

    pub async fn packages_for_type<TX: AsRef<Transactional>>(
        &self,
        r#type: &str,
        query: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<PackageSummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = package::Entity::find()
            .filter(package::Column::Type.eq(r#type))
            .filtering(query)?
            .limiting(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: PackageSummary::from_entities(&limiter.fetch().await?, &connection).await?,
            total,
        })
    }

    pub async fn package<TX: AsRef<Transactional>>(
        &self,
        r#type: &str,
        namespace: Option<String>,
        name: &str,
        tx: TX,
    ) -> Result<Option<PackageDetails>, Error> {
        let connection = self.db.connection(&tx);

        let mut query = package::Entity::find()
            .filter(package::Column::Type.eq(r#type))
            .filter(package::Column::Name.eq(name));

        if let Some(ns) = namespace {
            query = query.filter(package::Column::Namespace.eq(ns));
        } else {
            query = query.filter(package::Column::Namespace.is_null());
        }

        if let Some(package) = query.one(&connection).await? {
            Ok(Some(
                PackageDetails::from_entity(&package, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn package_version<TX: AsRef<Transactional>>(
        &self,
        r#type: &str,
        namespace: Option<String>,
        name: &str,
        version: &str,
        tx: TX,
    ) -> Result<Option<PackageVersionDetails>, Error> {
        let connection = self.db.connection(&tx);

        let mut query = package_version::Entity::find()
            .left_join(package::Entity)
            .filter(package::Column::Type.eq(r#type))
            .filter(package::Column::Name.eq(name))
            .filter(package_version::Column::Version.eq(version));

        if let Some(ns) = namespace {
            query = query.filter(package::Column::Namespace.eq(ns));
        } else {
            query = query.filter(package::Column::Namespace.is_null());
        }

        let package_version = query.one(&connection).await?;

        if let Some(package_version) = package_version {
            Ok(Some(
                PackageVersionDetails::from_entity(None, &package_version, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn package_by_uuid<TX: AsRef<Transactional>>(
        &self,
        package_version_uuid: &Uuid,
        tx: TX,
    ) -> Result<Option<PackageDetails>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(package) = package::Entity::find_by_id(*package_version_uuid)
            .one(&connection)
            .await?
        {
            Ok(Some(
                PackageDetails::from_entity(&package, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn package_version_by_uuid<TX: AsRef<Transactional>>(
        &self,
        package_version_uuid: &Uuid,
        tx: TX,
    ) -> Result<Option<PackageVersionDetails>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(package_version) = package_version::Entity::find_by_id(*package_version_uuid)
            .one(&connection)
            .await?
        {
            Ok(Some(
                PackageVersionDetails::from_entity(None, &package_version, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn qualified_package_by_uuid<TX: AsRef<Transactional>>(
        &self,
        qualified_package_uuid: &Uuid,
        tx: TX,
    ) -> Result<Option<QualifiedPackageDetails>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(qualified_package) =
            qualified_package::Entity::find_by_id(*qualified_package_uuid)
                .one(&connection)
                .await?
        {
            Ok(Some(
                QualifiedPackageDetails::from_entity(None, None, &qualified_package, &connection)
                    .await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn packages<TX: AsRef<Transactional>>(
        &self,
        query: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<PackageSummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = package::Entity::find().filtering(query)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: PackageSummary::from_entities(&limiter.fetch().await?, &connection).await?,
            total,
        })
    }

    pub async fn qualified_packages<TX: AsRef<Transactional>>(
        &self,
        query: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<QualifiedPackageSummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = qualified_package::Entity::find()
            .left_join(package_version::Entity)
            .filter(
                Condition::any().add(
                    package_version::Column::PackageId.in_subquery(
                        package::Entity::find()
                            .filtering(query)?
                            .select_only()
                            .column(package::Column::Id)
                            .into_query(),
                    ),
                ),
            )
            .limiting(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: QualifiedPackageSummary::from_entities(&limiter.fetch().await?, &connection)
                .await?,
            total,
        })
    }
}

#[cfg(test)]
mod test;
