use crate::service::{StorageBackend, StoreError};
use anyhow::Context;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use sha2::{digest::Output, Digest, Sha256};
use std::{
    fmt::Debug,
    io::ErrorKind,
    io::SeekFrom,
    path::{Path, PathBuf},
    pin::pin,
};
use tempfile::{tempdir, tempfile, TempDir};
use tokio::{
    fs::{create_dir_all, File},
    io::{AsyncSeekExt, AsyncWriteExt},
};
use tokio_util::io::ReaderStream;
use trustify_common::hash::{HashKey, HashKeyError};

/// A filesystem backed store
///
/// ## Layout
///
/// The layout of the filesystem is as follows:
///
/// ```ignore
/// <base>/
///   content/
///     <digest[0..2]>/
///       <digest[2..4]>/
///         <digest> # file
/// ```
///
/// The idea behind that is to limit the number of directory entries. For some filesystems,
/// the performance can degrade is directories get too big (have too many entries).
///
/// This layout limits the number of entries on the first two layers to 256, and limits the chance
/// of a file ending up in the same directory by 65536. Assuming an average distribution of hashes,
/// that would allow us to store 16777216 files, until we hit the cap of 256 entries in the lowest
/// lever directories. Should we need to increase that limit, we could easily add an additional
/// layer.
#[derive(Clone, Debug)]
pub struct FileSystemBackend {
    content: PathBuf,
}

const NUM_LEVELS: usize = 2;

impl FileSystemBackend {
    pub async fn new(base: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let base = base.into();
        let content = base.join("content");

        create_dir_all(&content)
            .await
            .or_else(|err| {
                if err.kind() == ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(err)
                }
            })
            .with_context(|| {
                format!(
                    "unable to create 'content' directory in the file system base: {}",
                    base.display()
                )
            })?;

        Ok(Self { content })
    }

    /// Create a new storage for testing
    pub async fn for_test() -> anyhow::Result<(Self, TempDir)> {
        let dir = tempdir()?;

        Self::new(dir.path()).await.map(|result| (result, dir))
    }
}

impl StorageBackend for FileSystemBackend {
    type Error = std::io::Error;

    async fn store<E, S>(&self, stream: S) -> Result<Output<Sha256>, StoreError<E, Self::Error>>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>,
    {
        // create a new temp file

        let mut file = File::from(tempfile().map_err(StoreError::Backend)?);

        // set up reader

        let mut stream = pin!(stream);
        let mut digest = Sha256::new();

        // process reader

        while let Some(next) = stream
            .next()
            .await
            .transpose()
            .map_err(StoreError::Stream)?
        {
            digest.update(&next);
            file.write_all(&next).await.map_err(StoreError::Backend)?;
        }

        // finalize the digest

        let digest = digest.finalize();

        // create the target path

        let hash = hex::encode(digest);
        let target = level_dir(&self.content, &hash, NUM_LEVELS);
        create_dir_all(&target).await.map_err(StoreError::Backend)?;
        let target = target.join(hash);

        let mut target = File::create(target).await.map_err(StoreError::Backend)?;

        // reset the file pointer to the start

        file.seek(SeekFrom::Start(0))
            .await
            .map_err(StoreError::Backend)?;

        // copy the content to the target file

        tokio::io::copy(&mut file, &mut target)
            .await
            .map_err(StoreError::Backend)?;

        // ensure we have all bytes on disk for the target file,
        // then close it

        target.flush().await.map_err(StoreError::Backend)?;
        drop(target);

        // the content is at the right place, close (destroy) the temp file

        drop(file);

        // done

        Ok(digest)
    }

    async fn retrieve(
        self,
        hash_key: HashKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>>>, Self::Error> {
        let hash = match hash_key {
            HashKey::Sha256(inner) => inner,
            HashKey::Sha384(inner) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    HashKeyError::UnsupportedAlgorithm(inner.clone()),
                ));
            }
            HashKey::Sha512(inner) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    HashKeyError::UnsupportedAlgorithm(inner.clone()),
                ));
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    HashKeyError::UnsupportedAlgorithm("unknown".to_string()),
                ));
            }
        };

        let target = level_dir(&self.content, &hash, NUM_LEVELS);
        create_dir_all(&target).await?;
        let target = target.join(hash);

        let file = match File::open(&target).await {
            Ok(file) => Some(file),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };

        Ok(file.map(ReaderStream::new))
    }
}

fn level_dir(base: impl AsRef<Path>, hash: &str, levels: usize) -> PathBuf {
    let prefixes = hash
        .chars()
        .take(levels * 2)
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect())
        .collect::<Vec<String>>();

    let mut path = base.as_ref().to_path_buf();

    for prefix in prefixes {
        path = path.join(prefix);
    }

    path
}

#[cfg(test)]
mod test {
    use super::*;
    use tempfile::tempdir;
    use test_log::test;

    #[test]
    fn test_level_dir() {
        assert_eq!(level_dir("/", "1234567890", 2), Path::new("/12/34"));
    }

    #[test(tokio::test)]
    async fn test_store() {
        const DIGEST: &str = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

        let dir = tempdir().unwrap();
        let backend = FileSystemBackend::new(dir.path()).await.unwrap();

        let digest = backend
            .store(ReaderStream::new(&b"Hello World"[..]))
            .await
            .expect("store must succeed");

        let hash = hex::encode(digest);
        assert_eq!(hash, DIGEST);

        let target = dir
            .path()
            .join("content")
            .join(&DIGEST[0..2])
            .join(&DIGEST[2..4])
            .join(DIGEST);

        assert!(target.exists());
        let data = std::fs::read(target).unwrap();
        assert_eq!(hex::encode(Sha256::digest(data)), DIGEST);

        drop(backend);
    }
}
