use crate::{
    graph::{sbom::cyclonedx, Graph},
    service::Error,
};
use cyclonedx_bom::prelude::Bom;
use std::io::Read;

pub struct CyclonedxLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CyclonedxLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load<L: Into<String>, R: Read>(
        &self,
        source: L,
        document: R,
        sha256: &str,
    ) -> Result<String, Error> {
        let sbom = Bom::parse_json_value(serde_json::from_reader(document)?)
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
                &source.into(),
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

        Ok(ctx.sbom.sbom_id.to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::graph::Graph;
    use crate::service::{Format, IngestorService};
    use bytes::Bytes;
    use futures::stream;
    use std::convert::Infallible;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::test::TrustifyContext;
    use trustify_module_storage::service::fs::FileSystemBackend;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_cyclonedx(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);
        let data = include_bytes!("../../../../../etc/test-data/zookeeper-3.9.2-cyclonedx.json");

        let (storage, _tmp) = FileSystemBackend::for_test().await?;

        let ingestor = IngestorService::new(graph, storage);

        ingestor
            .ingest(
                "test",
                None,
                Format::sbom_from_bytes(data)?,
                stream::iter([Ok::<_, Infallible>(Bytes::from_static(data))]),
            )
            .await
            .expect("must ingest");

        Ok(())
    }
}
