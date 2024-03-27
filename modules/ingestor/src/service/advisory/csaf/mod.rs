pub mod loader;
mod util;

use super::super::Error;
use crate::service::advisory::csaf::loader::CsafLoader;
use anyhow::anyhow;
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use std::time::Instant;
use trustify_common::db::Transactional;
use trustify_module_storage::service::{StorageBackend, SyncAdapter};

impl super::super::IngestorService {
    pub async fn ingest<S, E>(&self, source: &str, stream: S) -> Result<String, Error>
    where
        E: std::error::Error,
        S: Stream<Item = Result<Bytes, E>>,
    {
        let start = Instant::now();

        let digest = self
            .storage
            .store(stream)
            .await
            .map_err(|err| Error::Storage(anyhow!("{err}")))?;
        let sha256 = hex::encode(digest);

        let storage = SyncAdapter::new(self.storage.clone());
        let reader = storage
            .retrieve(sha256.clone())
            .await
            .map_err(Error::Storage)?
            .ok_or_else(|| Error::Storage(anyhow!("file went missing during upload")))?;

        let loader = CsafLoader::new(&self.graph);
        let result = loader.load(source, reader).await?;

        let duration = Instant::now() - start;
        log::info!(
            "Ingested: {} from {}: took {}",
            result,
            source,
            humantime::Duration::from(duration),
        );

        Ok(result)
    }

    pub async fn retrieve(
        &self,
        id: i32,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Error>>>, Error> {
        let Some(advisory) = self
            .graph
            .get_advisory_by_id(id, Transactional::None)
            .await?
        else {
            return Ok(None);
        };

        let hash = advisory.advisory.sha256;

        let stream = self
            .storage
            .clone()
            .retrieve(hash)
            .await
            .map_err(Error::Storage)?;

        Ok(stream.map(|stream| stream.map_err(Error::Storage)))
    }
}
