use crate::graph::{error::Error, Graph};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};
use sea_query::{OnConflict, SelectStatement};
use std::{
    collections::BTreeMap,
    fmt::{Debug, Formatter},
};
use tracing::instrument;
use trustify_common::{
    cpe::Cpe,
    db::{chunk::EntityChunkedIter, Transactional},
};
use trustify_entity::cpe;
use uuid::Uuid;

impl Graph {
    pub async fn get_cpe<C: Into<Cpe>, TX: AsRef<Transactional>>(
        &self,
        cpe: C,
        tx: TX,
    ) -> Result<Option<CpeContext>, Error> {
        let cpe = cpe.into();

        let query = cpe::Entity::find_by_id(cpe.uuid());

        if let Some(found) = query.one(&self.connection(&tx)).await? {
            Ok(Some((self, found).into()))
        } else {
            Ok(None)
        }
    }

    pub async fn get_cpe_by_query<TX: AsRef<Transactional>>(
        &self,
        query: SelectStatement,
        tx: TX,
    ) -> Result<Vec<CpeContext>, Error> {
        Ok(cpe::Entity::find()
            .filter(cpe::Column::Id.in_subquery(query))
            .all(&self.connection(&tx))
            .await?
            .into_iter()
            .map(|cpe22| (self, cpe22).into())
            .collect())
    }

    #[instrument(skip(self, tx), err(level=tracing::Level::INFO))]
    pub async fn ingest_cpe22<C, TX>(&self, cpe: C, tx: TX) -> Result<CpeContext, Error>
    where
        C: Into<Cpe> + Debug,
        TX: AsRef<Transactional>,
    {
        let cpe = cpe.into();

        if let Some(found) = self.get_cpe(cpe.clone(), &tx).await? {
            return Ok(found);
        }

        let entity: cpe::ActiveModel = cpe.into();

        Ok((self, entity.insert(&self.connection(&tx)).await?).into())
    }
}

#[derive(Clone)]
pub struct CpeContext {
    pub system: Graph,
    pub cpe: cpe::Model,
}

impl From<(&Graph, cpe::Model)> for CpeContext {
    fn from((system, cpe22): (&Graph, cpe::Model)) -> Self {
        Self {
            system: system.clone(),
            cpe: cpe22,
        }
    }
}

impl Debug for CpeContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.cpe.fmt(f)
    }
}

#[derive(Default, Debug)]
pub struct CpeCreator {
    /// CPEs to insert.
    ///
    /// Uses a [`BTreeMap`] to ensure order, avoiding deadlocks on the database
    cpes: BTreeMap<Uuid, cpe::ActiveModel>,
}

impl CpeCreator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, cpe: Cpe) {
        self.cpes.insert(cpe.uuid(), cpe.into());
    }

    #[instrument(skip(self, db), fields(num=self.cpes.len()), ret)]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        for batch in &self.cpes.into_values().chunked() {
            cpe::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([cpe::Column::Id])
                        .do_nothing()
                        .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_cpe(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);

        let cpe = Cpe::from_str("cpe:/a:redhat:enterprise_linux:9::crb")?;

        let c1 = graph.ingest_cpe22(cpe.clone(), ()).await?;
        let c2 = graph.ingest_cpe22(cpe, ()).await?;

        assert_eq!(c1.cpe.id, c2.cpe.id);

        Ok(())
    }
}
