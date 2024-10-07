use crate::{
    config::S3Config,
    service::{temp::TempFile, StorageBackend, StorageKey, StorageResult, StoreError},
};
use bytes::Bytes;
use futures::Stream;
use s3::{creds::Credentials, error::S3Error, Bucket};
use std::{fmt::Debug, pin::pin};

#[derive(Clone, Debug)]
pub struct S3Backend {
    bucket: Box<Bucket>,
}

impl S3Backend {
    pub async fn new(config: S3Config) -> Result<Self, S3Error> {
        let bucket = Bucket::new(
            &config.bucket.unwrap_or_default(),
            config.region.unwrap_or_default().parse()?,
            Credentials::new(
                config.access_key.as_deref(),
                config.secret_key.as_deref(),
                None,
                None,
                None,
            )?,
        )?;
        assert!(bucket.exists().await?, "S3 bucket not found");
        log::info!(
            "Using S3 bucket '{}' in '{}' for doc storage",
            bucket.name,
            bucket.region
        );
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
        let errhdlr = |e| StoreError::Backend(S3Error::Io(e));

        let stream = pin!(stream);
        let mut file = TempFile::new(stream).await.map_err(errhdlr)?;
        let mut source = file.reader().await.map_err(errhdlr)?;
        let result = file.result();

        self.bucket
            .put_object_stream(&mut source, result.key().to_string())
            .await
            .map_err(StoreError::Backend)?;

        Ok(result)
    }

    async fn retrieve<'a>(
        &self,
        StorageKey(key): StorageKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + 'a>, Self::Error> {
        match self.bucket.get_object_stream(key).await {
            Ok(resp) => Ok(Some(resp.bytes)),
            Err(S3Error::HttpFailWithBody(404, _)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
