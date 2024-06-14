pub mod dispatch;
pub mod fs;

use crate::service::fs::FileSystemBackend;
use bytes::{Bytes, BytesMut};
use futures::{Stream, TryStreamExt};
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::io::{Cursor, Read};
use trustify_common::hashing::Digests;
use trustify_common::id::Id;

#[derive(Debug, thiserror::Error)]
pub enum StoreError<S: Debug, B: Debug> {
    #[error("stream error: {0}")]
    Stream(#[source] S),
    #[error("backend error: {0}")]
    Backend(#[source] B),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorageKey(String);

impl Display for StorageKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Copy, Clone, Debug, thiserror::Error)]
pub enum StorageKeyError {
    #[error("Storage key must be of type SHA256")]
    WrongType,
}

impl TryFrom<Id> for StorageKey {
    type Error = StorageKeyError;

    fn try_from(value: Id) -> Result<Self, Self::Error> {
        match value {
            Id::Sha256(digest) => Ok(StorageKey(digest)),
            _ => Err(StorageKeyError::WrongType),
        }
    }
}

impl TryFrom<Vec<Id>> for StorageKey {
    type Error = StorageKeyError;

    fn try_from(value: Vec<Id>) -> Result<Self, Self::Error> {
        for id in value {
            if let Ok(id) = id.try_into() {
                return Ok(id);
            }
        }

        Err(StorageKeyError::WrongType)
    }
}

#[derive(Clone, Debug)]
pub struct StorageResult {
    pub key: StorageKey,
    pub digests: Digests,
}

pub trait StorageBackend {
    type Error: Debug;

    /// Store the content from a stream
    fn store<E, S>(
        &self,
        stream: S,
    ) -> impl Future<Output = Result<StorageResult, StoreError<E, Self::Error>>>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>;

    /// Retrieve the content as an async reader
    fn retrieve(
        self,
        key: StorageKey,
    ) -> impl Future<Output = Result<Option<impl Stream<Item = Result<Bytes, Self::Error>>>, Self::Error>>;
}

pub struct SyncAdapter<T: StorageBackend> {
    delegate: T,
}

impl<T: StorageBackend> SyncAdapter<T> {
    pub fn new(delegate: T) -> Self {
        SyncAdapter { delegate }
    }

    /// Retrieve the content as a sync reader, the operation itself is async
    ///
    /// NOTE: The default implementation falls back to an in-memory buffer.
    pub async fn retrieve(self, hash_key: StorageKey) -> Result<Option<impl Read>, T::Error>
    where
        Self: Sized,
    {
        Ok(match self.delegate.retrieve(hash_key).await? {
            Some(stream) => Some(Cursor::new(
                stream.try_collect::<BytesMut>().await?.freeze(),
            )),
            None => None,
        })
    }
}
