use crate::graph::sbom::clearly_defined::Curation;
use crate::graph::Graph;
use crate::model::IngestResult;
use crate::service::Error;
use serde_yml::Value;
use trustify_common::hashing::Digests;
use trustify_common::id::Id;
use trustify_entity::labels::Labels;

pub struct ClearlyDefinedLoader<'g> {
    graph: &'g Graph,
}

impl<'g> ClearlyDefinedLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load(
        &self,
        labels: Labels,
        yaml: Value,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let tx = self.graph.transaction().await?;
        let curation: Curation = serde_yml::from_value(yaml)?;

        let sbom = self
            .graph
            .ingest_sbom(labels, digests, &curation.document_id(), &curation, &tx)
            .await?;

        sbom.ingest_clearly_defined(curation, &tx)
            .await
            .map_err(Error::Generic)?;

        Ok(IngestResult {
            id: Id::Uuid(sbom.sbom.sbom_id),
            document_id: sbom.sbom.document_id,
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
    use trustify_test_context::document_bytes;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_clearly_defined(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());
        let (storage, _tmp) = FileSystemBackend::for_test().await?;
        let ingestor = IngestorService::new(graph, storage);

        let data = document_bytes("clearly-defined/chrono.yaml").await?;

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
