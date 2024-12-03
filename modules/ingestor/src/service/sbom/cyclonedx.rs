use crate::{
    graph::{sbom::cyclonedx, Graph},
    model::IngestResult,
    service::Error,
};
use cyclonedx_bom::prelude::Bom;
use sea_orm::TransactionTrait;
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id};
use trustify_entity::labels::Labels;

pub struct CyclonedxLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CyclonedxLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, sbom), ret)]
    pub async fn load(
        &self,
        labels: Labels,
        sbom: Bom,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let labels = labels.add("type", "cyclonedx");

        log::info!(
            "Storing - version: {}, serialNumber: {:?}",
            sbom.version,
            sbom.serial_number,
        );

        let tx = self.graph.db.begin().await?;

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
    use crate::service::IngestorService;
    use crate::{graph::Graph, service::Format};
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::{document_bytes, TrustifyContext};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let data = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone());

        ingestor
            .ingest(&data, Format::CycloneDX, ("source", "test"), None)
            .await
            .expect("must ingest");

        Ok(())
    }
}
