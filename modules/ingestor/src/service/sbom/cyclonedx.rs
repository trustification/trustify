use crate::{
    graph::{Graph, Outcome, sbom::cyclonedx},
    model::IngestResult,
    service::{Error, Metadata, Warnings},
};
use sea_orm::TransactionTrait;
use tracing::instrument;
use trustify_common::id::Id;

pub struct CyclonedxLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CyclonedxLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, buffer), err(level=tracing::Level::INFO))]
    pub async fn load(&self, metadata: Metadata, buffer: &[u8]) -> Result<IngestResult, Error> {
        let Metadata {
            labels,
            issuer: _,
            digests,
            signatures,
        } = metadata;

        let warnings = Warnings::default();

        let cdx: Box<serde_cyclonedx::cyclonedx::v_1_6::CycloneDx> = serde_json::from_slice(buffer)
            .map_err(|err| Error::UnsupportedFormat(format!("Failed to parse: {err}")))?;

        let labels = labels.add("type", "cyclonedx");

        log::info!(
            "Storing - version: {:?}, serialNumber: {:?}",
            cdx.version,
            cdx.serial_number,
        );

        let tx = self.graph.db.begin().await?;

        let document_id = cdx
            .serial_number
            .clone()
            .map(|sn| format!("{}/{}", sn, cdx.version.unwrap_or(0)))
            .or_else(|| {
                cdx.version.map(|v| v.to_string()) // If serial_number is None, just use version
            });

        let ctx = match self
            .graph
            .ingest_sbom(
                labels,
                &digests,
                document_id.clone(),
                cyclonedx::Information(&cdx),
                &tx,
            )
            .await?
        {
            Outcome::Existed(sbom) => sbom,
            Outcome::Added(sbom) => {
                sbom.ingest_cyclonedx(cdx, &warnings, &tx).await?;
                self.graph
                    .attach_signatures(sbom.sbom.source_document_id, signatures, &tx)
                    .await?;

                tx.commit().await?;

                sbom
            }
        };

        Ok(IngestResult {
            id: Id::Uuid(ctx.sbom.sbom_id),
            document_id,
            warnings: warnings.into(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        graph::Graph,
        service::{Format, Ingest, IngestorService},
    };
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::{TrustifyContext, document_bytes};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let data = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;

        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        ingestor
            .ingest(Ingest {
                data: &data,
                format: Format::CycloneDX,
                labels: ("source", "test").into(),
                ..Default::default()
            })
            .await
            .expect("must ingest");

        Ok(())
    }
}
