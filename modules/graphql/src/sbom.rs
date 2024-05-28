use async_graphql::{Context, FieldError, FieldResult, Object};
use std::sync::Arc;
use trustify_common::db::Transactional;
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
                location: sbom_context.sbom.location,
                sha256: sbom_context.sbom.sha256,
                document_id: sbom_context.sbom.document_id,
                published: sbom_context.sbom.published,
                authors: sbom_context.sbom.authors,
            }),
            Ok(None) => Err(FieldError::new("SBOM not found")),
            Err(err) => Err(FieldError::from(err)),
        }
    }

    async fn get_sboms_by_location<'a>(
        &self,
        ctx: &Context<'a>,
        location: String,
    ) -> FieldResult<Vec<Sbom>> {
        let graph = ctx.data::<Arc<Graph>>()?;
        let sboms = match graph
            .locate_sboms_by_location(&location, Transactional::None)
            .await
        {
            Ok(sbom) => sbom,
            _ => vec![],
        };

        sboms
            .into_iter()
            .map(|sbom| {
                Ok(Sbom {
                    sbom_id: sbom.sbom.sbom_id,
                    node_id: sbom.sbom.node_id,
                    location: sbom.sbom.location,
                    sha256: sbom.sbom.sha256,
                    document_id: sbom.sbom.document_id,
                    published: sbom.sbom.published,
                    authors: sbom.sbom.authors,
                })
            })
            .collect()
    }
}
