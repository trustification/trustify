use crate::service::{StorageBackend, StorageKey, StorageResult, StoreError};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};
use s3::{creds::Credentials, error::S3Error, Bucket, Region};
use std::{fmt::Debug, io, pin::pin};
use tokio_util::io::StreamReader;
use trustify_common::hashing::Contexts;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct S3Backend {
    bucket: Bucket,
}

impl S3Backend {}

impl S3Backend {
    pub fn new() -> Result<Self, S3Error> {
        // TODO: not this
        let bucket = Bucket::new(
            "trustify-jcrossley",
            Region::UsEast1,
            Credentials::default()?,
        )?;
        Ok(S3Backend { bucket })
    }
}

impl StorageBackend for S3Backend {
    type Error = S3Error;

    async fn store<E, S>(&self, stream: S) -> Result<StorageResult, StoreError<E, Self::Error>>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>,
    {
        let mut contexts = Contexts::new();
        let stream = pin!(stream.map(|item| {
            if let Ok(ref bytes) = item {
                contexts.update(bytes);
            }
            item
        }));

        // StreamReader requires std::io::Error items instead of Debug
        let stream = stream.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")));
        let mut rdr = StreamReader::new(stream);

        // Write the object with a temp key while digests are being calculated
        let path = format!("__temp__{}", Uuid::new_v4());
        self.bucket
            .put_object_stream(&mut rdr, &path)
            .await
            .map_err(StoreError::Backend)?;

        let result = StorageResult {
            digests: contexts.finish(),
        };
        let key: String = result.key().to_string();

        // Rename the object with a key calculated from its digests
        self.bucket
            .copy_object_internal(&path, &key)
            .await
            .map_err(StoreError::Backend)?;
        self.bucket
            .delete_object(&path)
            .await
            .map_err(StoreError::Backend)?;

        Ok(result)
    }

    async fn retrieve(
        self,
        StorageKey(key): StorageKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>>>, Self::Error> {
        match self.bucket.get_object_stream(key).await {
            Ok(resp) => Ok(Some(resp.bytes)),
            Err(S3Error::HttpFailWithBody(404, _)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
