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
        let storage = SyncAdapter::new(self.storage.clone());
        let data = storage
            .retrieve(sha256.clone())
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
        // FIXME: replace using only Value, once https://github.com/CycloneDX/cyclonedx-rust-cargo/pull/705 is released
        let sbom = Bom::parse_from_json(&*serde_json::to_vec(&json)?)
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
        Some("1.2") | Some("1.3") | Some("1.4")
    )
}
