use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::InnerSystem;
use huevos_common::purl::Purl;
use huevos_entity::scanner::Model;
use huevos_entity::{advisory, scanner, vulnerability, vulnerability_fixed};
use sea_orm::ActiveValue::Set;
use sea_orm::ColumnTrait;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryFilter};
use std::fmt::{Debug, Formatter};
use crate::system::cve::CveContext;

impl InnerSystem {
    pub async fn ingest_advisory(
        &self,
        identifier: &str,
        location: &str,
        sha256: &str,
        tx: Transactional<'_>,
    ) -> Result<AdvisoryContext, Error> {
        Ok(
            match advisory::Entity::find()
                .filter(advisory::Column::Identifier.eq(identifier.to_string()))
                .filter(advisory::Column::Location.eq(location.to_string()))
                .filter(advisory::Column::Sha256.eq(sha256.to_owned()))
                .one(&self.connection(tx))
                .await?
            {
                None => {
                    let entity = advisory::ActiveModel {
                        id: Default::default(),
                        identifier: Set(identifier.to_string()),
                        location: Set(location.to_string()),
                        sha256: Set(sha256.to_string()),
                    };

                    (self, entity.insert(&self.connection(tx)).await?).into()
                }
                Some(found) => (self, found).into(),
            },
        )
    }
}

pub struct AdvisoryContext {
    system: InnerSystem,
    advisory: advisory::Model,
}

impl Debug for AdvisoryContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.advisory.fmt(f)
    }
}

impl From<(&InnerSystem, advisory::Model)> for AdvisoryContext {
    fn from((system, advisory): (&InnerSystem, advisory::Model)) -> Self {
        Self {
            system: system.clone(),
            advisory
        }
    }
}

impl AdvisoryContext {

    pub async fn ingest_vulnerability<P: Into<Purl>>(&self, package: P, cve: CveContext) -> Result<(), Error> {
        todo!()
    }

}
