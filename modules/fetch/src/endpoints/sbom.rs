use crate::query::SearchOptions;
use crate::service::sbom::{SbomPackageReference, Which};
use crate::service::FetchService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;
use trustify_auth::{authenticator::user::UserInformation, authorizer::Authorizer, Permission};
use trustify_common::{model::Paginated, purl::Purl};
use trustify_entity::relationship::Relationship;

/// Search for SBOMs
#[utoipa::path(
    tag = "sbom",
    params(
        SearchOptions,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedSbomSummary),
    ),
)]
#[get("/api/v1/sbom")]
pub async fn all(
    fetch: web::Data<FetchService>,
    web::Query(search): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch.fetch_sboms(search, paginated, ()).await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Search for packages of an SBOM
#[utoipa::path(
    params(
        ("id", Path, description = "ID of the SBOM to get packages for"),
        SearchOptions,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedSbomPackage),
    ),
)]
#[get("/api/v1/sbom/{id}/packages")]
pub async fn packages(
    fetch: web::Data<FetchService>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch
        .fetch_sbom_packages(id.into_inner(), search, paginated, ())
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct RelatedQuery {
    /// The Package to use as reference
    pub reference: Option<String>,
    /// Which side the reference should be on
    #[serde(default)]
    pub which: Which,
    /// Optional relationship filter
    #[serde(default)]
    pub relationship: Option<Relationship>,
}

/// Search for related packages in an SBOM
#[utoipa::path(
    params(
        ("id", Path, description = "ID of SBOM to search packages in"),
        RelatedQuery,
        SearchOptions,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedSbomPackageRelation),
    ),
)]
#[get("/api/v1/sbom/{id}/related")]
pub async fn related(
    fetch: web::Data<FetchService>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(related): web::Query<RelatedQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = id.into_inner();

    let result = fetch
        .fetch_related_packages(
            id,
            search,
            paginated,
            related.which,
            match &related.reference {
                None => SbomPackageReference::Root,
                Some(id) => SbomPackageReference::Package(id),
            },
            related.relationship,
            (),
        )
        .await?;

    Ok(HttpResponse::Ok().json(result))
}
