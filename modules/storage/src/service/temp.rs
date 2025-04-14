use std::io::{Error, SeekFrom};
use tempfile::tempfile;
use tokio::{
    fs::File,
    io::{AsyncBufRead, AsyncRead, AsyncSeekExt, BufReader},
};
use trustify_common::hashing::{Digests, HashingRead};

use super::{Compression, StorageResult};

pub struct TempFile {
    file: File,
    digests: Digests,
}

/// Writes the contents of a stream to a temporary file and provides a
/// unique key for consumers to use to write the contents elsewhere,
/// e.g. Filesystem or S3.
impl TempFile {
    pub async fn new<S>(stream: S) -> Result<Self, Error>
    where
        S: AsyncRead + Unpin,
    {
        Self::with_compression(stream, Compression::None).await
    }

    /// Create a new temp file with compressed payload.
    ///
    /// The file will have the content of the reader, compressed using the provided algorithm. The
    /// digest however, will be from the original (uncompressed) payload.
    pub async fn with_compression<S>(stream: S, compression: Compression) -> Result<Self, Error>
    where
        S: AsyncRead + Unpin,
    {
        let mut file = File::from(tempfile()?);
        let mut reader = HashingRead::new(stream);
        compression.write(&mut reader, &mut file).await?;
        let digests = reader.digests();

        Ok(Self { file, digests })
    }

    /// Return a clone of the temp file after resetting its position
    pub async fn reader(&mut self) -> Result<impl AsyncBufRead + use<>, Error> {
        Ok(BufReader::new(self.file().await?))
    }

    /// Return a clone of the temp file
    pub async fn file(&self) -> Result<File, Error> {
        let mut file = self.file.try_clone().await?;
        file.seek(SeekFrom::Start(0)).await?;
        Ok(file)
    }

    /// Turn into a storage result
    pub fn to_result(&self) -> StorageResult {
        StorageResult {
            digests: self.digests,
        }
    }
}
