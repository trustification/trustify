pub mod dispatch;
pub mod fs;
pub mod s3;

mod compression;
mod temp;

pub use compression::Compression;

use crate::service::fs::FileSystemBackend;
use bytes::Bytes;
use futures::Stream;
use hex::ToHex;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
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
    pub digests: Digests,
}

impl StorageResult {
    pub fn key(&self) -> StorageKey {
        StorageKey(self.digests.sha256.encode_hex())
    }
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
    fn retrieve<'a>(
        &self,
        key: StorageKey,
    ) -> impl Future<
        Output = Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + 'a>, Self::Error>,
    >;
}
