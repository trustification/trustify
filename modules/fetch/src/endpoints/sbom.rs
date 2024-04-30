use crate::service::sbom::Which;
use crate::service::FetchService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_auth::{authenticator::user::UserInformation, authorizer::Authorizer, Permission};
use trustify_common::{model::Paginated, purl::Purl};
use trustify_entity::relationship::Relationship;
use trustify_module_search::model::SearchOptions;

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
    #[serde(default)]
    pub root: bool,
}

#[utoipa::path(
    params(
        ("id", Path, description = "SBOM id to get packages for")
    ),
    params(
        SearchOptions,
        Paginated,
        PackagesQuery,
    ),
    responses(
        (status = 200, description = "Packages"),
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
    #[serde(default)]
    pub which: Which,
    pub reference: Purl,
    #[serde(default)]
    pub relationship: Option<Relationship>,
}

#[utoipa::path(
    params(
        ("id", Path, description = "SBOM id to get packages for")
    ),
    params(
        SearchOptions,
        Paginated,
        RelatedQuery,
    ),
    responses(
        (status = 200, description = "Packages"),
    ),
)]
#[get("/{sbom_id}/related")]
pub async fn related(
    fetch: web::Data<FetchService>,
    sbom_id: web::Path<i32>,
    web::Query(search): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(related): web::Query<RelatedQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let sbom_id = sbom_id.into_inner();

    let result = fetch
        .fetch_related_packages(
            sbom_id,
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
