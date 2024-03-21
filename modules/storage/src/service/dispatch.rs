use super::*;
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use sha2::{digest::Output, Sha256};

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
}

impl StorageBackend for DispatchBackend {
    type Error = anyhow::Error;

    async fn store<E, S>(&self, stream: S) -> Result<Output<Sha256>, StoreError<E, Self::Error>>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>,
    {
        match self {
            Self::Filesystem(backend) => backend.store(stream).await.map_err(Self::map_err),
        }
    }

    async fn store_reader<R>(
        &self,
        reader: R,
    ) -> Result<Output<Sha256>, StoreError<std::io::Error, Self::Error>>
    where
        R: AsyncRead,
    {
        match self {
            Self::Filesystem(backend) => backend.store_reader(reader).await.map_err(Self::map_err),
        }
    }

    async fn retrieve(
        &self,
        hash: &str,
    ) -> Result<impl Stream<Item = Result<Bytes, Self::Error>>, Self::Error> {
        match self {
            Self::Filesystem(backend) => backend
                .retrieve(hash)
                .await
                .map(|stream| stream.map_err(anyhow::Error::from))
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
