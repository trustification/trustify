use bytes::Bytes;
use futures::{Stream, StreamExt};
use std::{
    fmt::Debug,
    io::{Error, SeekFrom},
    pin::pin,
};
use tempfile::tempfile;
use tokio::{
    fs::File,
    io::{AsyncBufRead, AsyncSeekExt, AsyncWriteExt, BufReader},
};
use trustify_common::hashing::{Contexts, Digests};

use super::StorageResult;

pub struct TempFile {
    file: File,
    digests: Digests,
}

/// Writes the contents of a stream to a temporary file and provides a
/// unique key for consumers to use to write the contents elsewhere,
/// e.g. Filesystem or S3.
impl TempFile {
    pub async fn new<S, E>(stream: S) -> Result<Self, Error>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>,
    {
        let mut file = File::from(tempfile()?);
        let mut stream = pin!(stream);
        let mut contexts = Contexts::new();

        while let Some(next) = stream
            .next()
            .await
            .transpose()
            .map_err(|e| Error::other(format!("{e:?}")))?
        {
            contexts.update(&next);
            file.write_all(&next).await?;
        }
        let digests = contexts.finish();

        Ok(Self { file, digests })
    }

    /// Return a clone of the temp file after resetting its position
    pub async fn reader(&mut self) -> Result<impl AsyncBufRead, Error> {
        self.file.seek(SeekFrom::Start(0)).await?;
        Ok(BufReader::new(self.file.try_clone().await?))
    }

    /// Passing self should ensure self.file is dropped and hence
    /// deleted from the filesystem
    pub fn result(self) -> StorageResult {
        StorageResult {
            digests: self.digests,
        }
    }
}
