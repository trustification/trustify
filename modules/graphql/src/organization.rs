use async_graphql::{Context, FieldError, FieldResult, Object};
use trustify_common::db::{self, Transactional};
use trustify_entity::organization::Model as Organization;
use trustify_module_ingestor::graph::Graph;

#[derive(Default)]
pub struct OrganizationQuery;

#[Object]
impl OrganizationQuery {
    async fn get_organization_by_name<'a>(
        &self,
        ctx: &Context<'a>,
        name: String,
    ) -> FieldResult<Organization> {
        let db = ctx.data::<db::Database>()?;
        let graph = Graph::new(db.clone());
        let organization = graph
            .get_organization_by_name(name, Transactional::None)
            .await;

        match organization {
            Ok(Some(organization)) => Ok(Organization {
                id: organization.organization.id,
                name: organization.organization.name,
                cpe_key: organization.organization.cpe_key,
                website: organization.organization.website,
            }),
            Ok(None) => Err(FieldError::new("Organization not found")),
            Err(err) => Err(FieldError::from(err)),
        }
    }
}
