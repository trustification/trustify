use crate::service::sbom::Which;
use crate::service::FetchService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_auth::{authenticator::user::UserInformation, authorizer::Authorizer, Permission};
use trustify_common::{model::Paginated, purl::Purl};
use trustify_entity::relationship::Relationship;
use trustify_module_search::model::SearchOptions;

/// Search for SBOMs
#[utoipa::path(
    context_path = "/api/v1/sbom",
    tag = "sbom",
    params(
        SearchOptions,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedSbomSummary),
    ),
)]
#[get("")]
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

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct PackagesQuery {
    /// Flag if only root level packages should be considered
    #[serde(default)]
    pub root: bool,
}

/// Search for packages of an SBOM
#[utoipa::path(
    context_path = "/api/v1/sbom",
    params(
        ("id", Path, description = "ID of the SBOM to get packages for"),
        PackagesQuery,
        SearchOptions,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedSbomPackage),
    ),
)]
#[get("/{id}/packages")]
pub async fn packages(
    fetch: web::Data<FetchService>,
    id: web::Path<i32>,
    web::Query(search): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(packages): web::Query<PackagesQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch
        .fetch_sbom_packages(id.into_inner(), search, paginated, packages.root, ())
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct RelatedQuery {
    /// The Package to use as reference
    pub reference: Purl,
    /// Which side the reference should be on
    #[serde(default)]
    pub which: Which,
    /// Optional relationship filter
    #[serde(default)]
    pub relationship: Option<Relationship>,
}

/// Search for related packages in an SBOM
#[utoipa::path(
    context_path = "/api/v1/sbom",
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
#[get("/{id}/related")]
pub async fn related(
    fetch: web::Data<FetchService>,
    id: web::Path<i32>,
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
            related.reference,
            related.relationship,
            (),
        )
        .await?;

    Ok(HttpResponse::Ok().json(result))
}
