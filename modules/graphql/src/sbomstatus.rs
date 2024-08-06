use actix_web::web;
use async_graphql::{Context, FieldResult, Object};
use trustify_common::db::{Database, Transactional};
use trustify_common::id::Id;
use trustify_module_fundamental::sbom::model::details::SbomStatus;
use trustify_module_fundamental::sbom::service::SbomService;
use uuid::Uuid;

#[derive(Default)]
pub struct SbomStatusQuery;

#[Object]
impl SbomStatusQuery {
    async fn cves_by_sbom<'a>(&self, ctx: &Context<'a>, id: Uuid) -> FieldResult<Vec<SbomStatus>> {
        let db = ctx.data::<Database>()?;
        let service = SbomService::new(db.clone());
        let sbom_service = web::Data::new(service);

        let sbom_details: Option<trustify_module_fundamental::sbom::model::details::SbomDetails> =
            match sbom_service
                .fetch_sbom(Id::Uuid(id), Transactional::None)
                .await
            {
                Ok(sbom) => sbom,
                _ => None,
            };

        match sbom_details {
            Some(sbom) => Ok(sbom.advisories[0].status.clone()),
            None => Ok(vec![]),
        }
    }
}
