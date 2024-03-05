use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::InnerSystem;
use trustify_common::cpe22::Component::Value;
use trustify_common::cpe22::{Component, Cpe22, Cpe22Type};
use trustify_entity as entity;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, NotSet, QueryFilter, Set};
use sea_query::SelectStatement;
use std::fmt::{Debug, Formatter};

impl InnerSystem {
    pub async fn get_cpe22<C: Into<Cpe22>>(
        &self,
        cpe: C,
        tx: Transactional<'_>,
    ) -> Result<Option<Cpe22Context>, Error> {
        let cpe = cpe.into();

        let mut query = entity::cpe22::Entity::find();

        query = match cpe.part() {
            Cpe22Type::Any => query.filter(entity::cpe22::Column::Part.eq("*")),
            Cpe22Type::Hardware => query.filter(entity::cpe22::Column::Part.eq("h")),
            Cpe22Type::OperatingSystem => query.filter(entity::cpe22::Column::Part.eq("o")),
            Cpe22Type::Application => query.filter(entity::cpe22::Column::Part.eq("a")),
        };

        query = match cpe.vendor() {
            Component::Any => query.filter(entity::cpe22::Column::Vendor.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe22::Column::Vendor.is_null()),
            Value(inner) => query.filter(entity::cpe22::Column::Vendor.eq(inner)),
        };

        query = match cpe.product() {
            Component::Any => query.filter(entity::cpe22::Column::Product.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe22::Column::Product.is_null()),
            Value(inner) => query.filter(entity::cpe22::Column::Product.eq(inner)),
        };

        query = match cpe.version() {
            Component::Any => query.filter(entity::cpe22::Column::Version.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe22::Column::Version.is_null()),
            Value(inner) => query.filter(entity::cpe22::Column::Version.eq(inner)),
        };

        query = match cpe.update() {
            Component::Any => query.filter(entity::cpe22::Column::Update.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe22::Column::Update.is_null()),
            Value(inner) => query.filter(entity::cpe22::Column::Update.eq(inner)),
        };

        query = match cpe.edition() {
            Component::Any => query.filter(entity::cpe22::Column::Edition.eq("*")),
            Component::NotApplicable => query.filter(entity::cpe22::Column::Edition.is_null()),
            Value(inner) => query.filter(entity::cpe22::Column::Edition.eq(inner)),
        };

        if let Some(found) = query.one(&self.connection(tx)).await? {
            Ok(Some((self, found).into()))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn get_cpe22_by_query(
        &self,
        query: SelectStatement,
        tx: Transactional<'_>,
    ) -> Result<Vec<Cpe22Context>, Error> {
        Ok(entity::cpe22::Entity::find()
            .filter(entity::cpe22::Column::Id.in_subquery(query))
            .all(&self.connection(tx))
            .await?
            .drain(0..)
            .map(|cpe22| (self, cpe22).into())
            .collect())
    }

    pub async fn ingest_cpe22<C: Into<Cpe22>>(
        &self,
        cpe: C,
        tx: Transactional<'_>,
    ) -> Result<Cpe22Context, Error> {
        let cpe = cpe.into();

        if let Some(found) = self.get_cpe22(cpe.clone(), tx).await? {
            return Ok(found);
        }

        let entity = entity::cpe22::ActiveModel {
            id: Default::default(),
            part: match cpe.part() {
                Cpe22Type::Any => Set(Some("*".to_string())),
                Cpe22Type::Hardware => Set(Some("h".to_string())),
                Cpe22Type::OperatingSystem => Set(Some("o".to_string())),
                Cpe22Type::Application => Set(Some("a".to_string())),
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

        Ok((self, entity.insert(&self.connection(tx)).await?).into())
    }
}

#[derive(Clone)]
pub struct Cpe22Context {
    pub system: InnerSystem,
    pub cpe22: entity::cpe22::Model,
}

impl From<(&InnerSystem, entity::cpe22::Model)> for Cpe22Context {
    fn from((system, cpe22): (&InnerSystem, entity::cpe22::Model)) -> Self {
        Self {
            system: system.clone(),
            cpe22,
        }
    }
}

impl Debug for Cpe22Context {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.cpe22.fmt(f)
    }
}
