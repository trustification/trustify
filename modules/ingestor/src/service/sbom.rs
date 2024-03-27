use crate::service::Error;
use anyhow::anyhow;
use bytes::Bytes;
use futures::Stream;
use std::time::Instant;
use trustify_common::db::Transactional;
use trustify_module_storage::service::{StorageBackend, SyncAdapter};

impl super::IngestorService {
    pub async fn ingest_sbom<S, E>(&self, source: &str, stream: S) -> Result<(), Error>
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
        let data = storage
            .retrieve(sha256.clone())
            .await
            .map_err(Error::Storage)?
            .ok_or_else(|| Error::Storage(anyhow!("File went missing during upload")))?;

        log::info!("Storing: {source}");

        let sbom = self
            .graph
            .ingest_sbom(source, &sha256, Transactional::None)
            .await?;

        // FIXME: consider adding a report entry in case of "fixing" things
        sbom.ingest_spdx_data(data).await.map_err(Error::Generic)?;

        let duration = Instant::now() - start;
        log::info!("Ingested - took {}", humantime::Duration::from(duration));

        Ok(())
    }
}
