pub mod dispatch;
pub mod fs;

use crate::service::fs::FileSystemBackend;
use bytes::{Bytes, BytesMut};
use futures::{Stream, TryStreamExt};
use sha2::{digest::Output, Sha256};
use std::fmt::Debug;
use std::future::Future;
use std::io::{Cursor, Read};
use trustify_common::hash::HashKey;

#[derive(Debug, thiserror::Error)]
pub enum StoreError<S: Debug, B: Debug> {
    #[error("stream error: {0}")]
    Stream(#[source] S),
    #[error("backend error: {0}")]
    Backend(#[source] B),
}

pub trait StorageBackend {
    type Error: Debug;

    /// Store the content from a stream
    fn store<E, S>(
        &self,
        stream: S,
    ) -> impl Future<Output = Result<Output<Sha256>, StoreError<E, Self::Error>>>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>;

    /// Retrieve the content as an async reader
    fn retrieve(
        self,
        hash_key: HashKey,
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
    pub async fn retrieve(self, hash_key: HashKey) -> Result<Option<impl Read>, T::Error>
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
