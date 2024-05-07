use crate::graph::sbom::spdx::{parse_spdx, Information};
use crate::service::Error;
use anyhow::anyhow;
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use std::time::Instant;
use trustify_common::db::Transactional;
use trustify_module_storage::service::{StorageBackend, SyncAdapter};

impl super::IngestorService {
    pub async fn ingest_sbom<S, E>(&self, source: &str, stream: S) -> Result<i32, Error>
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

        log::debug!("Source: {source}");

        // FIXME: consider adding a report entry in case of "fixing" things
        let (spdx, _) = parse_spdx(data)?;

        log::info!(
            "Storing: {}",
            spdx.document_creation_information.document_name
        );

        let tx = self.graph.transaction().await?;

        let document_id = &spdx.document_creation_information.spdx_document_namespace;

        let sbom = self
            .graph
            .ingest_sbom(source, &sha256, document_id, Information(&spdx), &tx)
            .await?;

        sbom.ingest_spdx(spdx, &tx).await.map_err(Error::Generic)?;

        tx.commit().await?;

        let duration = Instant::now() - start;
        log::info!("Ingested - took {}", humantime::Duration::from(duration));

        Ok(sbom.sbom.id)
    }
    pub async fn retrieve_sbom(
        &self,
        id: i32,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Error>>>, Error> {
        let Some(sbom) = self.graph.get_sbom_by_id(id, Transactional::None).await? else {
            return Ok(None);
        };

        let hash = sbom.sbom.sha256;

        let stream = self
            .storage
            .clone()
            .retrieve(hash)
            .await
            .map_err(Error::Storage)?;

        Ok(stream.map(|stream| stream.map_err(Error::Storage)))
    }
}
