use crate::{
    graph::sbom::{cyclonedx, spdx, spdx::parse_spdx},
    service::Error,
};
use anyhow::anyhow;
use bytes::Bytes;
use cyclonedx_bom::prelude::Bom;
use futures::Stream;
use serde_json::Value;
use std::time::Instant;
use trustify_common::hash::HashKey;
use trustify_module_storage::service::{StorageBackend, SyncAdapter};
use uuid::Uuid;

impl super::IngestorService {
    pub async fn ingest_sbom<S, E>(&self, source: &str, stream: S) -> Result<Uuid, Error>
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

        let hash_key = HashKey::Sha256(sha256.clone());

        let storage = SyncAdapter::new(self.storage.clone());
        let data = storage
            .retrieve(hash_key)
            .await
            .map_err(Error::Storage)?
            .ok_or_else(|| Error::Storage(anyhow!("File went missing during upload")))?;

        log::debug!("Source: {source}");

        let json: Value = serde_json::from_reader(data)?;

        let result = if is_spdx(&json) {
            Ok(self.ingest_spdx(json, source, &sha256).await?)
        } else if is_cyclonedx(&json) {
            Ok(self.ingest_cyclonedx(json, source, &sha256).await?)
        } else {
            Err(Error::UnsupportedFormat("Unsupported format".to_string()))
        };

        // log duration

        let duration = Instant::now() - start;
        log::info!("Ingested - took {}", humantime::Duration::from(duration));

        // return

        result
    }

    async fn ingest_spdx(&self, json: Value, source: &str, sha256: &str) -> Result<Uuid, Error> {
        // FIXME: consider adding a report entry in case of "fixing" things
        let (spdx, _) = parse_spdx(json)?;

        log::info!(
            "Storing: {}",
            spdx.document_creation_information.document_name
        );

        let tx = self.graph.transaction().await?;

        let document_id = &spdx.document_creation_information.spdx_document_namespace;

        let sbom = self
            .graph
            .ingest_sbom(source, sha256, document_id, spdx::Information(&spdx), &tx)
            .await?;

        sbom.ingest_spdx(spdx, &tx).await.map_err(Error::Generic)?;

        tx.commit().await?;

        Ok(sbom.sbom.sbom_id)
    }

    async fn ingest_cyclonedx(
        &self,
        json: Value,
        source: &str,
        sha256: &str,
    ) -> Result<Uuid, Error> {
        let sbom = Bom::parse_json_value(json)
            .map_err(|err| Error::UnsupportedFormat(format!("Failed to parse: {err}")))?;

        log::info!(
            "Storing - version: {}, serialNumber: {:?}",
            sbom.version,
            sbom.serial_number,
        );

        let tx = self.graph.transaction().await?;

        let document_id = sbom
            .serial_number
            .as_ref()
            .map(|uuid| uuid.to_string())
            .unwrap_or_else(|| sbom.version.to_string());

        let ctx = self
            .graph
            .ingest_sbom(
                source,
                sha256,
                &document_id,
                cyclonedx::Information(&sbom),
                &tx,
            )
            .await?;

        ctx.ingest_cyclonedx(sbom, &tx)
            .await
            .map_err(Error::Generic)?;

        tx.commit().await?;

        Ok(ctx.sbom.sbom_id)
    }
}

/// check if this is a spdx file we support
fn is_spdx(json: &Value) -> bool {
    matches!(
        json["spdxVersion"].as_str(),
        Some("SPDX-2.2") | Some("SPDX-2.3")
    )
}

/// check if this is a cyclonedx file we support
fn is_cyclonedx(json: &Value) -> bool {
    matches!(
        json["specVersion"].as_str(),
        Some("1.3") | Some("1.4") | Some("1.5")
    )
}

#[cfg(test)]
mod test {
    use crate::graph::Graph;
    use crate::service::IngestorService;
    use bytes::Bytes;
    use futures::stream;
    use std::convert::Infallible;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::test::TrustifyContext;
    use trustify_module_storage::service::fs::FileSystemBackend;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn basic_sbom_test(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);
        let data = include_bytes!(
            "../../../../../etc/test-data/quarkus-bom-2.13.8.Final-redhat-00004.json"
        );

        let (storage, _tmp) = FileSystemBackend::for_test().await?;

        let ingestor = IngestorService::new(graph, storage);

        ingestor
            .ingest_sbom(
                "test",
                stream::iter([Ok::<_, Infallible>(Bytes::from_static(data))]),
            )
            .await
            .expect("must ingest");

        Ok(())
    }
}
