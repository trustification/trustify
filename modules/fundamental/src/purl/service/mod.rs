use crate::{
    purl::model::{
        details::{
            base_purl::BasePurlDetails, purl::PurlDetails, versioned_purl::VersionedPurlDetails,
        },
        summary::{base_purl::BasePurlSummary, purl::PurlSummary, r#type::TypeSummary},
    },
    Error,
};
use sea_orm::{
    prelude::Uuid, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, IntoSimpleExpr,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait,
};
use sea_query::{Condition, Expr, Order, SimpleExpr};
use tracing::instrument;
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Filtering, Query},
        Database, Transactional,
    },
    model::{Paginated, PaginatedResults},
    purl::{Purl, PurlErr},
};
use trustify_entity::{base_purl, qualified_purl, versioned_purl};
use trustify_module_ingestor::common::Deprecation;

pub struct PurlService {
    db: Database,
}

impl PurlService {
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

        let ecosystems: Vec<_> = base_purl::Entity::find()
            .select_only()
            .column(base_purl::Column::Type)
            .group_by(base_purl::Column::Type)
            .distinct()
            .order_by(base_purl::Column::Type, Order::Asc)
            .into_model::<Ecosystem>()
            .all(&connection)
            .await?
            .into_iter()
            .map(|e| e.r#type)
            .collect();

        TypeSummary::from_names(&ecosystems, &connection).await
    }

    pub async fn base_purls_by_type<TX: AsRef<Transactional>>(
        &self,
        r#type: &str,
        query: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(r#type))
            .filtering(query)?
            .limiting(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&limiter.fetch().await?, &connection).await?,
            total,
        })
    }

    pub async fn base_purl<TX: AsRef<Transactional>>(
        &self,
        r#type: &str,
        namespace: Option<String>,
        name: &str,
        tx: TX,
    ) -> Result<Option<BasePurlDetails>, Error> {
        let connection = self.db.connection(&tx);

        let mut query = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(r#type))
            .filter(base_purl::Column::Name.eq(name));

        if let Some(ns) = namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        if let Some(package) = query.one(&connection).await? {
            Ok(Some(
                BasePurlDetails::from_entity(&package, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl<TX: AsRef<Transactional>>(
        &self,
        r#type: &str,
        namespace: Option<String>,
        name: &str,
        version: &str,
        tx: TX,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        let connection = self.db.connection(&tx);

        let mut query = versioned_purl::Entity::find()
            .left_join(base_purl::Entity)
            .filter(base_purl::Column::Type.eq(r#type))
            .filter(base_purl::Column::Name.eq(name))
            .filter(versioned_purl::Column::Version.eq(version));

        if let Some(ns) = namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        let package_version = query.one(&connection).await?;

        if let Some(package_version) = package_version {
            Ok(Some(
                VersionedPurlDetails::from_entity(None, &package_version, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn base_purl_by_uuid<TX: AsRef<Transactional>>(
        &self,
        package_version_uuid: &Uuid,
        tx: TX,
    ) -> Result<Option<BasePurlDetails>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(package) = base_purl::Entity::find_by_id(*package_version_uuid)
            .one(&connection)
            .await?
        {
            Ok(Some(
                BasePurlDetails::from_entity(&package, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn base_purl_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
        tx: TX,
    ) -> Result<Option<BasePurlDetails>, Error> {
        let connection = self.db.connection(&tx);
        let mut query = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(&purl.ty))
            .filter(base_purl::Column::Name.eq(&purl.name));

        if let Some(ns) = &purl.namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        if let Some(base_purl) = query.one(&connection).await? {
            Ok(Some(
                BasePurlDetails::from_entity(&base_purl, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl_by_uuid<TX: AsRef<Transactional>>(
        &self,
        purl_version_uuid: &Uuid,
        tx: TX,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(package_version) = versioned_purl::Entity::find_by_id(*purl_version_uuid)
            .one(&connection)
            .await?
        {
            Ok(Some(
                VersionedPurlDetails::from_entity(None, &package_version, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
        tx: TX,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(version) = &purl.version {
            let mut query = versioned_purl::Entity::find()
                .left_join(base_purl::Entity)
                .filter(base_purl::Column::Type.eq(&purl.ty))
                .filter(base_purl::Column::Name.eq(&purl.name))
                .filter(versioned_purl::Column::Version.eq(version));

            if let Some(ns) = &purl.namespace {
                query = query.filter(base_purl::Column::Namespace.eq(ns));
            } else {
                query = query.filter(base_purl::Column::Namespace.is_null());
            }

            let package_version = query.one(&connection).await?;

            if let Some(package_version) = package_version {
                Ok(Some(
                    VersionedPurlDetails::from_entity(None, &package_version, &connection).await?,
                ))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::Purl(PurlErr::MissingVersion(
                "A versioned pURL requires a version".to_string(),
            )))
        }
    }

    pub async fn purl_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
        deprecation: Deprecation,
        tx: TX,
    ) -> Result<Option<PurlDetails>, Error> {
        let connection = self.db.connection(&tx);
        if let Some(version) = &purl.version {
            let mut query = qualified_purl::Entity::find()
                .left_join(versioned_purl::Entity)
                .left_join(base_purl::Entity)
                .filter(base_purl::Column::Type.eq(&purl.ty))
                .filter(base_purl::Column::Name.eq(&purl.name))
                .filter(versioned_purl::Column::Version.eq(version));

            if let Some(ns) = &purl.namespace {
                query = query.filter(base_purl::Column::Namespace.eq(ns));
            } else {
                query = query.filter(base_purl::Column::Namespace.is_null());
            }

            let purl = query.one(&connection).await?;

            if let Some(purl) = purl {
                Ok(Some(
                    PurlDetails::from_entity(None, None, &purl, deprecation, &connection).await?,
                ))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::Purl(PurlErr::MissingVersion(
                "A fully-qualified pURL requires a version".to_string(),
            )))
        }
    }

    #[instrument(skip(self, tx), err(level=tracing::Level::INFO))]
    pub async fn purl_by_uuid<TX: AsRef<Transactional>>(
        &self,
        purl_uuid: &Uuid,
        deprecation: Deprecation,
        tx: TX,
    ) -> Result<Option<PurlDetails>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(qualified_package) = qualified_purl::Entity::find_by_id(*purl_uuid)
            .one(&connection)
            .await?
        {
            Ok(Some(
                PurlDetails::from_entity(None, None, &qualified_package, deprecation, &connection)
                    .await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn base_purls<TX: AsRef<Transactional>>(
        &self,
        query: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = base_purl::Entity::find().filtering(query)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&limiter.fetch().await?, &connection).await?,
            total,
        })
    }

    #[instrument(skip(self, tx), err)]
    pub async fn purls<TX: AsRef<Transactional>>(
        &self,
        query: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<PurlSummary>, Error> {
        let connection = self.db.connection(&tx);

        // TODO: this would be the condition used to select from jsonb name key
        let _unused_condition = Expr::cust_with_exprs(
            "$1->>'name' ~~* $2",
            [
                qualified_purl::Column::Purl.into_simple_expr(),
                SimpleExpr::Value(format!("%{}%", query.q).into()),
            ],
        );

        // TODO: we need to figure out how we bring in querying keys of jsonb column in query.rs
        let limiter = qualified_purl::Entity::find()
            .left_join(versioned_purl::Entity)
            .filter(
                Condition::any().add(
                    versioned_purl::Column::BasePurlId.in_subquery(
                        base_purl::Entity::find()
                            .filtering(query)?
                            .select_only()
                            .column(base_purl::Column::Id)
                            .into_query(),
                    ),
                ),
            )
            .limiting(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: PurlSummary::from_entities(&limiter.fetch().await?, &connection).await?,
            total,
        })
    }

    #[instrument(skip(self, tx), err)]
    pub async fn gc_purls<TX: AsRef<Transactional>>(&self, tx: TX) -> Result<u64, Error> {
        let connection = self.db.connection(&tx);

        let res = connection
            .execute_unprepared(include_str!("gc_purls.sql"))
            .await?;

        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod test;
