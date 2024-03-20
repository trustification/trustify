use crate::graph::error::Error;
use crate::graph::Graph;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, NotSet, QueryFilter, Set};
use sea_query::SelectStatement;
use std::fmt::{Debug, Formatter};
use trustify_common::cpe::Component::Value;
use trustify_common::cpe::{Component, Cpe, CpeType};
use trustify_common::db::Transactional;
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
        };

        query = match cpe.vendor() {
            Component::Any => query.filter(entity::cpe::Column::Vendor.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Vendor.is_null()),
            Value(inner) => query.filter(entity::cpe::Column::Vendor.eq(inner)),
        };

        query = match cpe.product() {
            Component::Any => query.filter(entity::cpe::Column::Product.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Product.is_null()),
            Value(inner) => query.filter(entity::cpe::Column::Product.eq(inner)),
        };

        query = match cpe.version() {
            Component::Any => query.filter(entity::cpe::Column::Version.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Version.is_null()),
            Value(inner) => query.filter(entity::cpe::Column::Version.eq(inner)),
        };

        query = match cpe.update() {
            Component::Any => query.filter(entity::cpe::Column::Update.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Update.is_null()),
            Value(inner) => query.filter(entity::cpe::Column::Update.eq(inner)),
        };

        query = match cpe.edition() {
            Component::Any => query.filter(entity::cpe::Column::Edition.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe::Column::Edition.is_null()),
            Value(inner) => query.filter(entity::cpe::Column::Edition.eq(inner)),
        };

        if let Some(found) = query.one(&self.connection(&tx)).await? {
            Ok(Some((self, found).into()))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn get_cpe_by_query<TX: AsRef<Transactional>>(
        &self,
        query: SelectStatement,
        tx: TX,
    ) -> Result<Vec<CpeContext>, Error> {
        Ok(entity::cpe::Entity::find()
            .filter(entity::cpe::Column::Id.in_subquery(query))
            .all(&self.connection(&tx))
            .await?
            .drain(0..)
            .map(|cpe22| (self, cpe22).into())
            .collect())
    }

    pub async fn ingest_cpe22<C: Into<Cpe>, TX: AsRef<Transactional>>(
        &self,
        cpe: C,
        tx: TX,
    ) -> Result<CpeContext, Error> {
        let cpe = cpe.into();

        if let Some(found) = self.get_cpe(cpe.clone(), &tx).await? {
            return Ok(found);
        }

        let entity = entity::cpe::ActiveModel {
            id: Default::default(),
            part: match cpe.part() {
                CpeType::Any => Set(Some("*".to_string())),
                CpeType::Hardware => Set(Some("h".to_string())),
                CpeType::OperatingSystem => Set(Some("o".to_string())),
                CpeType::Application => Set(Some("a".to_string())),
            },
            vendor: match cpe.vendor() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            product: match cpe.product() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            version: match cpe.version() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            update: match cpe.update() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            edition: match cpe.edition() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            language: Default::default(),
        };

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
