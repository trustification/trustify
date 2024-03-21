use super::super::Error;
use anyhow::anyhow;
use bytes::Bytes;
use csaf::Csaf;
use futures::Stream;
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
                .retrieve_sync(&sha256)
                .await
                .map_err(Error::Storage)?,
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
}
