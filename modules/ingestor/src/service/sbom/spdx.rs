use crate::{
    graph::{
        sbom::spdx::{self, parse_spdx},
        Graph,
    },
    service::Error,
};
use std::io::Read;
use trustify_common::id::Id;

pub struct SpdxLoader<'g> {
    graph: &'g Graph,
}

impl<'g> SpdxLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load<L: Into<String>, R: Read>(
        &self,
        source: L,
        json: R,
        sha256: &str,
    ) -> Result<Id, Error> {
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
            .ingest_sbom(
                &source.into(),
                sha256,
                document_id,
                spdx::Information(&spdx),
                &tx,
            )
            .await?;

        sbom.ingest_spdx(spdx, &tx).await.map_err(Error::Generic)?;

        tx.commit().await?;

        Ok(Id::Uuid(sbom.sbom.sbom_id))
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
    async fn ingest_spdx(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);
        let data = include_bytes!("../../../../../etc/test-data/ubi9-9.2-755.1697625012.json");

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
