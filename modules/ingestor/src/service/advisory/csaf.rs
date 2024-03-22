use super::super::Error;
use anyhow::anyhow;
use bytes::Bytes;
use csaf::Csaf;
use futures::{Stream, TryStreamExt};
use std::time::Instant;
use trustify_common::db::Transactional;
use trustify_module_storage::service::StorageBackend;

impl super::super::IngestorService {
    pub async fn ingest<S, E>(&self, source: &str, stream: S) -> Result<i32, Error>
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

        let csaf: Csaf = serde_json::from_reader(
            self.storage
                .clone()
                .retrieve_sync(sha256.clone())
                .await
                .map_err(Error::Storage)?
                .ok_or_else(|| Error::Storage(anyhow!("file went missing during upload")))?,
        )?;

        let identifier = csaf.document.tracking.id.clone();

        let advisory = self
            .graph
            .ingest_advisory(&identifier, source, sha256, Transactional::None)
            .await?;

        advisory.ingest_csaf(csaf).await?;

        let duration = Instant::now() - start;
        log::info!(
            "Ingested: {} from {}: took {}",
            identifier,
            source,
            humantime::Duration::from(duration),
        );

        Ok(advisory.advisory.id)
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
