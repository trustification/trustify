pub mod advisory;
pub mod organization;
pub mod sbom;
pub mod vulnerability;

use async_graphql::MergedObject;

#[derive(MergedObject, Default)]
pub struct RootQuery(
    advisory::AdvisoryQuery,
    organization::OrganizationQuery,
    sbom::SbomQuery,
    vulnerability::VulnerabilityQuery,
);
