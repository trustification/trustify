use super::{super::Error, Format};
use crate::service::advisory::{csaf::loader::CsafLoader, osv::loader::OsvLoader};
use anyhow::anyhow;
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use std::time::Instant;
use trustify_common::db::Transactional;
use trustify_module_storage::service::{StorageBackend, SyncAdapter};

pub mod loader;
mod util;

impl super::super::IngestorService {
    pub async fn ingest<S, E>(&self, source: &str, fmt: Format, stream: S) -> Result<String, Error>
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

        let result = match fmt {
            Format::CSAF => {
                let loader = CsafLoader::new(&self.graph);
                loader.load(source, reader, &sha256).await?
            }
            Format::OSV => {
                let loader = OsvLoader::new(&self.graph);
                loader.load(source, reader, &sha256).await?
            }
        };

        let duration = Instant::now() - start;
        log::info!(
            "Ingested: {} from {}: took {}",
            result,
            source,
            humantime::Duration::from(duration),
        );

        Ok(result)
    }

    pub async fn retrieve_advisory(
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
