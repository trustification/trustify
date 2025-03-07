pub mod advisory;
pub mod cpe;
pub mod db_context;
pub mod error;
pub mod organization;
pub mod product;
pub mod purl;
pub mod sbom;
pub mod vulnerability;

use db_context::DbContext;
use hex::ToHex;
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait, TryInsertResult};
use sea_query::OnConflict;
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::Arc,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::source_document;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Graph {
    pub(crate) db: trustify_common::db::Database,
    pub(crate) db_context: Arc<Mutex<DbContext>>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error<E: Send> {
    #[error(transparent)]
    Database(#[from] DbErr),
    #[error(transparent)]
    Transaction(E),
}

impl Graph {
    pub fn new(db: trustify_common::db::Database) -> Self {
        Self {
            db,
            db_context: Arc::new(Mutex::new(DbContext::new())),
        }
    }

    /// Create a new source document, or return an existing sha256 digest if a document with that
    /// already sha256 digest already exists.
    #[instrument(skip(self, connection, f), err(level=tracing::Level::INFO))]
    async fn create_doc<C: ConnectionTrait, T, F>(
        &self,
        digests: &Digests,
        connection: &C,
        f: F,
    ) -> Result<CreateOutcome<T>, error::Error>
    where
        F: AsyncFnOnce(String) -> Result<Option<T>, error::Error>,
    {
        let doc_model = source_document::ActiveModel {
            id: Default::default(),
            sha256: Set(digests.sha256.encode_hex()),
            sha384: Set(digests.sha384.encode_hex()),
            sha512: Set(digests.sha512.encode_hex()),
            size: Set(digests.size as i64),
            ingested: Set(OffsetDateTime::now_utc()),
        };

        let doc = source_document::Entity::insert(doc_model)
            .on_conflict(
                OnConflict::column(source_document::Column::Sha256)
                    .do_nothing()
                    .to_owned(),
            )
            .do_nothing()
            .exec(connection)
            .await?;

        match doc {
            TryInsertResult::Empty => Err(error::Error::Database(DbErr::Custom(
                "empty insert data".to_string(),
            ))),
            TryInsertResult::Conflicted => match f(digests.sha256.encode_hex()).await? {
                Some(doc) => Ok(CreateOutcome::Exists(doc)),
                None => Err(error::Error::Database(DbErr::Custom(
                    "document vanished".to_string(),
                ))),
            },
            TryInsertResult::Inserted(doc) => Ok(CreateOutcome::Created(doc.last_insert_id)),
        }
    }
}

#[derive(Debug)]
enum CreateOutcome<T> {
    Created(Uuid),
    Exists(T),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    Existed(T),
    Added(T),
}

impl<T> Outcome<T> {
    pub fn into_inner(self) -> T {
        match self {
            Outcome::Existed(value) => value,
            Outcome::Added(value) => value,
        }
    }
}

impl<T> Deref for Outcome<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Outcome::Existed(value) => value,
            Outcome::Added(value) => value,
        }
    }
}

impl<T> DerefMut for Outcome<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Outcome::Existed(value) => value,
            Outcome::Added(value) => value,
        }
    }
}
