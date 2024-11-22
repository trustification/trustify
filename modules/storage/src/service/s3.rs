use crate::{
    config::S3Config,
    service::{
        compression::Compression, temp::TempFile, StorageBackend, StorageKey, StorageResult,
        StoreError,
    },
};
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use http::{header::CONTENT_ENCODING, HeaderMap, HeaderValue};
use s3::{creds::Credentials, error::S3Error, Bucket};
use std::{fmt::Debug, io, pin::pin, str::FromStr};
use tokio_util::io::{ReaderStream, StreamReader};

#[derive(Clone, Debug)]
pub struct S3Backend {
    bucket: Bucket,
    compression: Compression,
}

impl S3Backend {
    pub async fn new(config: S3Config, compression: Compression) -> Result<Self, S3Error> {
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
        )?
        .with_extra_headers(HeaderMap::from_iter([(
            CONTENT_ENCODING,
            HeaderValue::from_str(&compression.to_string())?,
        )]))?;
        log::info!(
            "Using S3 bucket '{}' in '{}' for doc storage",
            bucket.name,
            bucket.region
        );
        Ok(S3Backend {
            bucket,
            compression,
        })
    }
}

impl StorageBackend for S3Backend {
    type Error = Error;

    async fn store<E, S>(&self, stream: S) -> Result<StorageResult, StoreError<E, Self::Error>>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>,
    {
        let stream = pin!(stream);
        let mut file = TempFile::new(stream).await.map_err(Error::Io)?;
        let mut source = self
            .compression
            .compress(file.reader().await.map_err(Error::Io)?)
            .await;
        let result = file.result();

        self.bucket
            .put_object_stream(&mut source, result.key().to_string())
            .await
            .map_err(Error::S3)?;

        Ok(result)
    }

    async fn retrieve<'a>(
        &self,
        StorageKey(key): StorageKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + 'a>, Self::Error> {
        let (head, _status) = self.bucket.head_object(&key).await?;
        let encoding = head
            .content_encoding
            .unwrap_or(Compression::None.to_string());
        let compression = Compression::from_str(&encoding)?;
        match self.bucket.get_object_stream(&key).await {
            Ok(resp) => {
                let reader = StreamReader::new(resp.bytes.map_err(|e| match e {
                    S3Error::Io(e) => e,
                    _ => io::Error::new(io::ErrorKind::Other, e),
                }));
                Ok(Some(
                    ReaderStream::new(compression.reader(reader)).map_err(Error::Io),
                ))
            }
            Err(S3Error::HttpFailWithBody(404, _)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    S3(#[from] S3Error),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Parse(#[from] strum::ParseError),
}

impl<E: Debug> From<Error> for StoreError<E, Error> {
    fn from(e: Error) -> Self {
        StoreError::Backend(e)
    }
}
