use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use sea_orm::{
    prelude::Uuid, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    TransactionTrait,
};
use sea_query::{Alias, Expr, OnConflict};
use trustify_common::{db::Database, error::ErrorInformation, model::Revisioned};
use trustify_entity::user_preferences;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mid air collision")]
    MidAirCollision,
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
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

#[derive(Clone, Debug)]
pub struct UserPreferenceService {
    db: Database,
}

impl UserPreferenceService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn set(
        &self,
        user_id: String,
        key: String,
        expected_revision: Option<&str>,
        data: serde_json::Value,
    ) -> Result<Revisioned<()>, Error> {
        let next = Uuid::new_v4();

        match expected_revision {
            Some(expected_revision) => {
                // if we expect a revision, just update
                let result = user_preferences::Entity::update_many()
                    .col_expr(user_preferences::Column::Data, Expr::value(data))
                    .col_expr(user_preferences::Column::Revision, Expr::value(next))
                    .filter(user_preferences::Column::UserId.eq(user_id))
                    .filter(user_preferences::Column::Key.eq(key))
                    .filter(
                        user_preferences::Column::Revision
                            .into_expr()
                            .cast_as(Alias::new("text"))
                            .eq(expected_revision),
                    )
                    .exec(&self.db)
                    .await?;

                if result.rows_affected == 0 {
                    // we expected a revision, but didn't find one, we don't update it, but fail
                    Err(Error::MidAirCollision)
                } else {
                    Ok(Revisioned {
                        value: (),
                        revision: next.to_string(),
                    })
                }
            }
            None => {
                let on_conflict = OnConflict::columns([
                    user_preferences::Column::UserId,
                    user_preferences::Column::Key,
                ])
                .values([
                    (user_preferences::Column::Revision, next.into()),
                    (user_preferences::Column::Data, data.clone().into()),
                ])
                .to_owned();

                user_preferences::Entity::insert(user_preferences::ActiveModel {
                    user_id: Set(user_id),
                    key: Set(key),
                    revision: Set(next),
                    data: Set(data),
                })
                .on_conflict(on_conflict)
                .exec_without_returning(&self.db)
                .await?;

                Ok(Revisioned {
                    value: (),
                    revision: next.to_string(),
                })
            }
        }
    }

    pub async fn get(
        &self,
        user_id: String,
        key: String,
    ) -> Result<Option<Revisioned<serde_json::Value>>, Error> {
        let result = user_preferences::Entity::find_by_id((user_id, key))
            .one(&self.db)
            .await?;

        Ok(result.map(|result| Revisioned {
            value: result.data,
            revision: result.revision.to_string(),
        }))
    }

    pub async fn delete(
        &self,
        user_id: String,
        key: String,
        expected_revision: Option<&str>,
    ) -> Result<bool, Error> {
        let mut delete = user_preferences::Entity::delete_many()
            .filter(user_preferences::Column::UserId.eq(&user_id))
            .filter(user_preferences::Column::Key.eq(&key));

        if let Some(revision) = expected_revision {
            delete = delete.filter(
                user_preferences::Column::Revision
                    .into_expr()
                    .cast_as(Alias::new("text"))
                    .eq(revision),
            );
        }

        let tx = self.db.begin().await?;

        let result = delete.exec(&tx).await?;

        let result = if expected_revision.is_some() && result.rows_affected == 0 {
            // now we need to figure out if the item wasn't there or if it was modified
            if user_preferences::Entity::find_by_id((user_id, key))
                .count(&tx)
                .await?
                == 0
            {
                Ok(false)
            } else {
                Err(Error::MidAirCollision)
            }
        } else {
            Ok(result.rows_affected > 0)
        };

        tx.commit().await?;

        result
    }
}
