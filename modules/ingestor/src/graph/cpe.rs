use crate::graph::{error::Error, Graph};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use sea_query::SelectStatement;
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Debug, Formatter},
};
use tracing::instrument;
use trustify_common::{
    cpe::{Component, Cpe, CpeType, Language},
    db::Transactional,
};
use trustify_entity as entity;

impl Graph {
    pub async fn get_cpe<C: Into<Cpe>, TX: AsRef<Transactional>>(
        &self,
        cpe: C,
        tx: TX,
    ) -> Result<Option<CpeContext>, Error> {
        let cpe = cpe.into();

        let mut query = entity::cpe::Entity::find();

        query = match cpe.part() {
            CpeType::Any => query.filter(entity::cpe::Column::Part.eq("*")),
            CpeType::Hardware => query.filter(entity::cpe::Column::Part.eq("h")),
            CpeType::OperatingSystem => query.filter(entity::cpe::Column::Part.eq("o")),
            CpeType::Application => query.filter(entity::cpe::Column::Part.eq("a")),
            CpeType::Empty => query.filter(entity::cpe::Column::Part.is_null()),
        };

        query = match cpe.vendor() {
            Component::Any => query.filter(entity::cpe::Column::Vendor.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Vendor.is_null()),
            Component::Value(inner) => query.filter(entity::cpe::Column::Vendor.eq(inner)),
        };

        query = match cpe.product() {
            Component::Any => query.filter(entity::cpe::Column::Product.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Product.is_null()),
            Component::Value(inner) => query.filter(entity::cpe::Column::Product.eq(inner)),
        };

        query = match cpe.version() {
            Component::Any => query.filter(entity::cpe::Column::Version.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Version.is_null()),
            Component::Value(inner) => query.filter(entity::cpe::Column::Version.eq(inner)),
        };

        query = match cpe.update() {
            Component::Any => query.filter(entity::cpe::Column::Update.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Update.is_null()),
            Component::Value(inner) => query.filter(entity::cpe::Column::Update.eq(inner)),
        };

        query = match cpe.edition() {
            Component::Any => query.filter(entity::cpe::Column::Edition.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Edition.is_null()),
            Component::Value(inner) => query.filter(entity::cpe::Column::Edition.eq(inner)),
        };

        query = match cpe.language() {
            Language::Any => query.filter(entity::cpe::Column::Language.eq("*")),
            Language::Language(inner) => query.filter(entity::cpe::Column::Language.eq(inner)),
        };

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
        Ok(entity::cpe::Entity::find()
            .filter(entity::cpe::Column::Id.in_subquery(query))
            .all(&self.connection(&tx))
            .await?
            .into_iter()
            .map(|cpe22| (self, cpe22).into())
            .collect())
    }

    #[instrument(skip(self, tx), err)]
    pub async fn ingest_cpe22<C, TX>(&self, cpe: C, tx: TX) -> Result<CpeContext, Error>
    where
        C: Into<Cpe> + Debug,
        TX: AsRef<Transactional>,
    {
        let cpe = cpe.into();

        if let Some(found) = self.get_cpe(cpe.clone(), &tx).await? {
            return Ok(found);
        }

        let entity: entity::cpe::ActiveModel = cpe.into();

        Ok((self, entity.insert(&self.connection(&tx)).await?).into())
    }
}

#[derive(Clone)]
pub struct CpeContext {
    pub system: Graph,
    pub cpe: entity::cpe::Model,
}

impl From<(&Graph, entity::cpe::Model)> for CpeContext {
    fn from((system, cpe22): (&Graph, entity::cpe::Model)) -> Self {
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

#[derive(Debug)]
pub struct CpeCreator {
    graph: Graph,
    cpes: HashMap<Cpe, CpeContext>,
}

impl CpeCreator {
    pub fn new(graph: Graph) -> Self {
        Self {
            graph,
            cpes: Default::default(),
        }
    }

    pub async fn ingest(
        &mut self,
        cpe: Cpe,
        tx: impl AsRef<Transactional>,
    ) -> Result<CpeContext, Error> {
        match self.cpes.entry(cpe) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let cpe = self.graph.ingest_cpe22(entry.key().clone(), tx).await?;
                Ok(entry.insert(cpe).clone())
            }
        }
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
