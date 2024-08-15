use self::s3::S3Backend;

use super::*;
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};

/// A common backend, dispatching to the ones we support.
///
/// This is required due to the "can't turn into object" problem, which we encounter for this trait
/// (due to using async traits and function level type arguments). The only alternative would be
/// to propagate the specific type up to the root level. However, that would also mean that actix
/// handlers would be required to know about that full type to extract it as application
/// data.
///
/// NOTE: Right now we only have one type (filesystem), but the goal is to have an additional one
/// soon (e.g. S3)
#[derive(Clone, Debug)]
pub enum DispatchBackend {
    Filesystem(FileSystemBackend),
    S3(S3Backend),
}

impl StorageBackend for DispatchBackend {
    type Error = anyhow::Error;

    async fn store<E, S>(&self, stream: S) -> Result<StorageResult, StoreError<E, Self::Error>>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>,
    {
        match self {
            Self::Filesystem(backend) => backend.store(stream).await.map_err(Self::map_err),
            Self::S3(backend) => backend.store(stream).await.map_err(Self::map_err),
        }
    }

    async fn retrieve<'a>(
        &self,
        key: StorageKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + 'a>, Self::Error>
    where
        Self: Sized,
    {
        match self {
            Self::Filesystem(backend) => backend
                .retrieve(key)
                .await
                .map(|stream| stream.map(|stream| stream.map_err(anyhow::Error::from).boxed()))
                .map_err(anyhow::Error::from),
            Self::S3(backend) => backend
                .retrieve(key)
                .await
                .map(|stream| stream.map(|stream| stream.map_err(anyhow::Error::from).boxed()))
                .map_err(anyhow::Error::from),
        }
    }
}

impl DispatchBackend {
    /// convert any backend error to [`anyhow::Error`].
    fn map_err<S, B>(error: StoreError<S, B>) -> StoreError<S, anyhow::Error>
    where
        S: Debug,
        B: std::error::Error + Send + Sync + 'static,
    {
        match error {
            StoreError::Stream(err) => StoreError::Stream(err),
            StoreError::Backend(err) => StoreError::Backend(anyhow::Error::from(err)),
        }
    }
}

impl From<FileSystemBackend> for DispatchBackend {
    fn from(value: FileSystemBackend) -> Self {
        Self::Filesystem(value)
    }
}
