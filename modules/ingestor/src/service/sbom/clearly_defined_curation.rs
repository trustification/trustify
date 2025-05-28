use crate::{
    graph::{Graph, Outcome, sbom::clearly_defined::Curation},
    model::IngestResult,
    service::Error,
};
use sea_orm::TransactionTrait;
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id};
use trustify_entity::labels::Labels;

pub struct ClearlyDefinedCurationLoader<'g> {
    graph: &'g Graph,
}

impl<'g> ClearlyDefinedCurationLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, curation), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: Labels,
        curation: Curation,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let tx = self.graph.db.begin().await?;

        let document_id = curation.document_id().clone();
        let sbom = match self
            .graph
            .ingest_sbom(labels, digests, Some(document_id.clone()), &curation, &tx)
            .await?
        {
            Outcome::Existed(sbom) => sbom,
            Outcome::Added(sbom) => {
                sbom.ingest_clearly_defined_curation(curation, &tx, sbom.sbom.sbom_id)
                    .await
                    .map_err(Error::Generic)?;

                tx.commit().await?;

                sbom
            }
        };

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
    use crate::service::{Cache, Format, IngestorService};
    use sea_orm::{EntityTrait, FromQueryResult, QuerySelect, RelationTrait};
    use sea_query::JoinType;
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::{license, sbom_package_license};
    use trustify_test_context::{TrustifyContext, document_bytes};
    #[derive(Debug, FromQueryResult)]
    struct PackageLicenseInfo {
        pub node_id: String,
        pub license_expression: String,
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_clearly_defined(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());
        let ingestor = IngestorService::new(graph, ctx.storage.clone(), Default::default());

        let data = document_bytes("clearly-defined/chrono.yaml").await?;

        ingestor
            .ingest(
                &data,
                Format::ClearlyDefinedCuration,
                ("source", "test"),
                None,
                Cache::Skip,
            )
            .await
            .expect("must ingest");

        let result: Vec<PackageLicenseInfo> = sbom_package_license::Entity::find()
            .join(
                JoinType::Join,
                sbom_package_license::Relation::License.def(),
            )
            .select_only()
            .column_as(sbom_package_license::Column::NodeId, "node_id")
            .column_as(license::Column::Text, "license_expression")
            .into_model::<PackageLicenseInfo>()
            .all(&ctx.db)
            .await?;

        assert_eq!(1, result.len());
        assert_eq!("Apache-2.0 OR MIT", result[0].license_expression);
        assert_eq!("ClearlyDefinedCuration", result[0].node_id);

        Ok(())
    }
}
