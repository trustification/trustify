use std::sync::Arc;

use async_graphql::{Context, FieldError, FieldResult, Object};
use trustify_common::db::Transactional;
use trustify_entity::labels::Labels;
use trustify_entity::sbom::Model as Sbom;
use trustify_module_ingestor::graph::Graph;
use uuid::Uuid;

#[derive(Default)]
pub struct SbomQuery;

#[Object]
impl SbomQuery {
    async fn get_sbom_by_id<'a>(&self, ctx: &Context<'a>, id: Uuid) -> FieldResult<Sbom> {
        let graph = ctx.data::<Arc<Graph>>()?;
        let sbom = graph.locate_sbom_by_id(id, Transactional::None).await;

        match sbom {
            Ok(Some(sbom_context)) => Ok(Sbom {
                sbom_id: sbom_context.sbom.sbom_id,
                node_id: sbom_context.sbom.node_id,
                labels: sbom_context.sbom.labels,
                document_id: sbom_context.sbom.document_id,
                published: sbom_context.sbom.published,
                authors: sbom_context.sbom.authors,
                source_document_id: sbom_context.sbom.source_document_id,
                data_licenses: sbom_context.sbom.data_licenses,
            }),
            Ok(None) => Err(FieldError::new("SBOM not found")),
            Err(err) => Err(FieldError::from(err)),
        }
    }

    async fn get_sboms_by_labels<'a>(
        &self,
        ctx: &Context<'a>,
        labels: String,
    ) -> FieldResult<Vec<Sbom>> {
        let graph = ctx.data::<Arc<Graph>>()?;

        let mut local_labels = Labels::new();
        let labs = labels.split(',');
        for item in labs {
            let mut label = item.split(':');
            local_labels.insert(
                label.next().unwrap_or("").split_whitespace().collect(),
                label.next().unwrap_or("").split_whitespace().collect(),
            );
        }

        let sboms = graph
            .locate_sboms_by_labels(local_labels, Transactional::None)
            .await
            .unwrap_or_default();

        sboms
            .into_iter()
            .map(|sbom| {
                Ok(Sbom {
                    sbom_id: sbom.sbom.sbom_id,
                    node_id: sbom.sbom.node_id,
                    labels: sbom.sbom.labels,
                    document_id: sbom.sbom.document_id,
                    published: sbom.sbom.published,
                    authors: sbom.sbom.authors,
                    source_document_id: sbom.sbom.source_document_id,
                    data_licenses: sbom.sbom.data_licenses,
                })
            })
            .collect()
    }
}
