use async_graphql::{Context, FieldError, FieldResult, Object};
use trustify_common::db::{self, Transactional};
use trustify_entity::advisory::Model as Advisory;
use trustify_module_ingestor::graph::Graph;
use uuid::Uuid;

#[derive(Default)]
pub struct AdvisoryQuery;

#[Object]
impl AdvisoryQuery {
    async fn get_advisory_by_id<'a>(&self, ctx: &Context<'a>, id: Uuid) -> FieldResult<Advisory> {
        let db = ctx.data::<db::Database>()?;
        let graph = Graph::new(db.clone());
        let advisory = graph.get_advisory_by_id(id, Transactional::None).await;

        match advisory {
            Ok(Some(advisory)) => Ok(Advisory {
                id: advisory.advisory.id,
                identifier: advisory.advisory.identifier,
                issuer_id: advisory.advisory.issuer_id,
                labels: advisory.advisory.labels,
                sha256: advisory.advisory.sha256,
                sha384: advisory.advisory.sha384,
                sha512: advisory.advisory.sha512,
                published: advisory.advisory.published,
                modified: advisory.advisory.modified,
                withdrawn: advisory.advisory.withdrawn,
                title: advisory.advisory.title,
            }),
            Ok(None) => Err(FieldError::new("Advisory not found")),
            Err(err) => Err(FieldError::from(err)),
        }
    }

    async fn get_advisories<'a>(&self, ctx: &Context<'a>) -> FieldResult<Vec<Advisory>> {
        let db = ctx.data::<db::Database>()?;
        let graph = Graph::new(db.clone());

        let advisories = match graph.get_advisories(Transactional::None).await {
            Ok(advisory) => advisory,
            _ => vec![],
        };

        log::info!("advisories: {:?}", advisories);
        advisories
            .into_iter()
            .map(|advisory| {
                Ok(Advisory {
                    id: advisory.advisory.id,
                    identifier: advisory.advisory.identifier,
                    issuer_id: advisory.advisory.issuer_id,
                    labels: advisory.advisory.labels,
                    sha256: advisory.advisory.sha256,
                    sha384: advisory.advisory.sha384,
                    sha512: advisory.advisory.sha512,
                    published: advisory.advisory.published,
                    modified: advisory.advisory.modified,
                    withdrawn: advisory.advisory.withdrawn,
                    title: advisory.advisory.title,
                })
            })
            .collect()
    }
}
