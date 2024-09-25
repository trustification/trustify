use std::sync::Arc;

use async_graphql::{Context, FieldError, FieldResult, Object};
use trustify_common::db::Transactional;
use trustify_entity::advisory::Model as Advisory;
use trustify_module_ingestor::graph::Graph;
use uuid::Uuid;

#[derive(Default)]
pub struct AdvisoryQuery;

#[Object]
impl AdvisoryQuery {
    async fn get_advisory_by_id<'a>(&self, ctx: &Context<'a>, id: Uuid) -> FieldResult<Advisory> {
        let graph = ctx.data::<Arc<Graph>>()?;
        let advisory = graph.get_advisory_by_id(id, Transactional::None).await;

        match advisory {
            Ok(Some(advisory)) => Ok(Advisory {
                id: advisory.advisory.id,
                identifier: advisory.advisory.identifier,
                deprecated: advisory.advisory.deprecated,
                version: advisory.advisory.version,
                issuer_id: advisory.advisory.issuer_id,
                labels: advisory.advisory.labels,
                published: advisory.advisory.published,
                modified: advisory.advisory.modified,
                withdrawn: advisory.advisory.withdrawn,
                title: advisory.advisory.title,
                source_document_id: advisory.advisory.source_document_id,
            }),
            Ok(None) => Err(FieldError::new("Advisory not found")),
            Err(err) => Err(FieldError::from(err)),
        }
    }

    async fn get_advisories<'a>(&self, ctx: &Context<'a>) -> FieldResult<Vec<Advisory>> {
        let graph = ctx.data::<Arc<Graph>>()?;

        let advisories = match graph
            .get_advisories(Default::default(), Transactional::None)
            .await
        {
            Ok(advisories) => advisories,
            _ => vec![],
        };

        advisories
            .into_iter()
            .map(|advisory| {
                Ok(Advisory {
                    id: advisory.advisory.id,
                    identifier: advisory.advisory.identifier,
                    deprecated: advisory.advisory.deprecated,
                    version: advisory.advisory.version,
                    issuer_id: advisory.advisory.issuer_id,
                    labels: advisory.advisory.labels,
                    published: advisory.advisory.published,
                    modified: advisory.advisory.modified,
                    withdrawn: advisory.advisory.withdrawn,
                    title: advisory.advisory.title,
                    source_document_id: advisory.advisory.source_document_id,
                })
            })
            .collect()
    }
}
