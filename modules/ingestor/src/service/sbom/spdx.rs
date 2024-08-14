use crate::service::Warnings;
use crate::{
    graph::{
        sbom::spdx::{self, parse_spdx},
        Graph,
    },
    model::IngestResult,
    service::Error,
};
use serde_json::Value;
use trustify_common::{hashing::Digests, id::Id};
use trustify_entity::labels::Labels;

pub struct SpdxLoader<'g> {
    graph: &'g Graph,
}

impl<'g> SpdxLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load(
        &self,
        labels: Labels,
        json: Value,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::default();

        let (spdx, _) = parse_spdx(&warnings, json)?;

        log::info!(
            "Storing: {}",
            spdx.document_creation_information.document_name
        );

        let tx = self.graph.transaction().await?;

        let labels = labels.add("type", "spdx");

        let document_id = spdx
            .document_creation_information
            .spdx_document_namespace
            .clone();

        let sbom = self
            .graph
            .ingest_sbom(labels, digests, &document_id, spdx::Information(&spdx), &tx)
            .await?;

        sbom.ingest_spdx(spdx, &warnings, &tx).await?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(sbom.sbom.sbom_id),
            document_id,
            warnings: warnings.into(),
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
    async fn ingest_spdx(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db.clone();
        let graph = Graph::new(db);
        let data = document_bytes("ubi9-9.2-755.1697625012.json").await?;

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
