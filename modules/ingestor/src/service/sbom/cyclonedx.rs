use crate::model::IngestResult;
use crate::{
    graph::{sbom::cyclonedx, Graph},
    service::Error,
};
use cyclonedx_bom::prelude::Bom;
use std::io::Read;
use trustify_common::{hashing::Digests, id::Id};
use trustify_entity::labels::Labels;

pub struct CyclonedxLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CyclonedxLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load<R: Read>(
        &self,
        labels: Labels,
        document: R,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let sbom = Bom::parse_json_value(serde_json::from_reader(document)?)
            .map_err(|err| Error::UnsupportedFormat(format!("Failed to parse: {err}")))?;

        let labels = labels.add("type", "cyclonedx");

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
                labels,
                digests,
                &document_id,
                cyclonedx::Information(&sbom),
                &tx,
            )
            .await?;

        ctx.ingest_cyclonedx(sbom, &tx)
            .await
            .map_err(Error::Generic)?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(ctx.sbom.sbom_id),
            document_id,
            warnings: vec![],
        })
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
    use trustify_module_storage::service::fs::FileSystemBackend;
    use trustify_test_context::{document_bytes, TrustifyContext};

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_cyclonedx(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);
        let data = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;

        let (storage, _tmp) = FileSystemBackend::for_test().await?;

        let ingestor = IngestorService::new(graph, storage);

        ingestor
            .ingest(
                ("source", "test"),
                None,
                Format::sbom_from_bytes(&data)?,
                stream::iter([Ok::<_, Infallible>(Bytes::copy_from_slice(&data))]),
            )
            .await
            .expect("must ingest");

        Ok(())
    }
}
