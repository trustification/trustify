use crate::model::{ImportConfiguration, Revisioned};
use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    TransactionTrait,
};
use sea_query::Expr;
use serde_json::Value;
use trustify_common::db::Database;
use trustify_common::error::ErrorInformation;
use trustify_entity::importer;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("importer '{0}' already exists")]
    AlreadyExists(String),
    #[error("importer '{0}' not found")]
    NotFound(String),
    #[error("mid air collision")]
    MidAirCollision,
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Error::AlreadyExists(_) => HttpResponse::Conflict().json(ErrorInformation {
                error: "AlreadyExists".into(),
                message: self.to_string(),
                details: None,
            }),
            Error::NotFound(_) => HttpResponse::Conflict().json(ErrorInformation {
                error: "NotFound".into(),
                message: self.to_string(),
                details: None,
            }),
            Error::MidAirCollision => HttpResponse::PreconditionFailed().json(ErrorInformation {
                error: "MidAirCollision".into(),
                message: self.to_string(),
                details: None,
            }),
            _ => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Internal".into(),
                message: self.to_string(),
                details: None,
            }),
        }
    }
}

pub struct ImporterService {
    db: Database,
}

impl ImporterService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list(&self) -> Result<Vec<ImportConfiguration>, Error> {
        let result = importer::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();

        Ok(result)
    }

    pub async fn create(&self, name: String, configuration: Value) -> Result<(), Error> {
        let tx = self.db.begin().await?;

        let entity = importer::ActiveModel {
            name: Set(name),
            revision: Set(Uuid::new_v4()),
            configuration: Set(configuration),
        };

        entity.insert(&tx).await?;

        tx.commit().await?;

        Ok(())
    }

    pub async fn read(&self, name: &str) -> Result<Option<Revisioned<ImportConfiguration>>, Error> {
        let result = importer::Entity::find_by_id(name).one(&self.db).await?;

        Ok(result.map(Into::into))
    }

    pub async fn update(
        &self,
        name: String,
        configuration: Value,
        expected_revision: Option<&str>,
    ) -> Result<(), Error> {
        let mut update = importer::Entity::update_many()
            .col_expr(importer::Column::Configuration, Expr::value(configuration))
            .filter(importer::Column::Name.eq(&name));

        if let Some(revision) = expected_revision {
            update = update.filter(importer::Column::Revision.eq(revision));
        }

        let result = update.exec(&self.db).await?;

        if result.rows_affected == 0 {
            // now we need to figure out if the item wasn't there or if it was modified
            if importer::Entity::find_by_id(&name).count(&self.db).await? == 0 {
                Err(Error::NotFound(name))
            } else {
                Err(Error::MidAirCollision)
            }
        } else {
            Ok(())
        }
    }

    pub async fn delete(&self, name: &str, expected_revision: Option<&str>) -> Result<bool, Error> {
        let mut delete = importer::Entity::delete_many().filter(importer::Column::Name.eq(name));

        if let Some(revision) = expected_revision {
            delete = delete.filter(importer::Column::Revision.eq(revision));
        }

        let result = delete.exec(&self.db).await?;

        Ok(result.rows_affected > 0)
    }
}
