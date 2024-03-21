pub mod dispatch;
pub mod fs;

use crate::service::fs::FileSystemBackend;
use bytes::{Bytes, BytesMut};
use futures::{Stream, TryStreamExt};
use sha2::{digest::Output, Sha256};
use std::fmt::Debug;
use std::future::Future;
use std::io::{Cursor, Read};
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

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

    /// Store the content from a reader
    fn store_reader<R>(
        &self,
        reader: R,
    ) -> impl Future<Output = Result<Output<Sha256>, StoreError<std::io::Error, Self::Error>>>
    where
        R: AsyncRead,
    {
        async { self.store(ReaderStream::new(reader)).await }
    }

    /// Retrieve the content as an async reader
    fn retrieve(
        &self,
        hash: &str,
    ) -> impl Future<Output = Result<impl Stream<Item = Result<Bytes, Self::Error>>, Self::Error>>;

    /// Retrieve the content as a sync reader, the operation itself is async
    ///
    /// NOTE: The default implementation falls back to an in-memory buffer.
    fn retrieve_sync(&self, hash: &str) -> impl Future<Output = Result<impl Read, Self::Error>> {
        async { self.retrieve_buf(hash).await.map(Cursor::new) }
    }

    /// Retrieve the content as a byte buffer
    fn retrieve_buf(&self, hash: &str) -> impl Future<Output = Result<Bytes, Self::Error>> {
        async {
            let buf = self.retrieve(hash).await?.try_collect::<BytesMut>().await?;
            Ok(buf.freeze())
        }
    }
}
