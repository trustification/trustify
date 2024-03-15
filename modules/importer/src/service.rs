use crate::model::ImportConfiguration;
use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{ActiveModelTrait, DbErr, EntityTrait, TransactionTrait};
use serde_json::Value;
use trustify_common::db::Database;
use trustify_common::error::ErrorInformation;
use trustify_entity::importer;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("importer '{0}' already exists")]
    AlreadyExists(String),
    #[error("importer '{0}' not found")]
    NotFound(String),
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
            configuration: Set(configuration),
        };

        entity.insert(&tx).await?;

        tx.commit().await?;

        Ok(())
    }

    pub async fn read(&self, name: &str) -> Result<Option<ImportConfiguration>, Error> {
        let result = importer::Entity::find_by_id(name).one(&self.db).await?;

        Ok(result.map(Into::into))
    }

    pub async fn update(&self, name: String, configuration: Value) -> Result<(), Error> {
        let entity = importer::ActiveModel {
            name: Unchanged(name.clone()),
            configuration: Set(configuration),
        };

        entity.update(&self.db).await.map_err(|err| match err {
            DbErr::RecordNotUpdated => Error::NotFound(name),
            err => err.into(),
        })?;

        Ok(())
    }

    pub async fn delete(&self, name: &str) -> Result<bool, Error> {
        let result = importer::Entity::delete_by_id(name).exec(&self.db).await?;

        Ok(result.rows_affected > 0)
    }
}
