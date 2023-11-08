use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::InnerSystem;
use huevos_entity::{scanner, vulnerability, vulnerability_fixed};
use huevos_entity::scanner::Model;
use sea_orm::ActiveValue::Set;
use sea_orm::ColumnTrait;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryFilter};
use std::fmt::{Debug, Formatter};
use huevos_common::purl::Purl;

impl InnerSystem {
    pub async fn ingest_scanner(
        &self,
        name: &str,
        tx: Transactional<'_>,
    ) -> Result<ScannerContext, Error> {
        Ok(
            match scanner::Entity::find()
                .filter(scanner::Column::Name.eq(name.to_string()))
                .one(&self.connection(tx))
                .await?
            {
                None => {
                    let entity = scanner::ActiveModel {
                        id: Default::default(),
                        name: Set(name.to_string()),
                    };

                    (self, entity.insert(&self.connection(tx)).await?).into()
                }
                Some(found) => (self, found).into(),
            },
        )
    }
}

pub struct ScannerContext {
    pub(crate) system: InnerSystem,
    pub(crate) scanner: scanner::Model,
}

impl Debug for ScannerContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.scanner.fmt(f)
    }
}

impl From<(&InnerSystem, scanner::Model)> for ScannerContext {
    fn from((system, scanner): (&InnerSystem, Model)) -> Self {
        Self {
            system: system.clone(),
            scanner,
        }
    }
}

impl ScannerContext {


}
