use crate::service::FetchService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_auth::authenticator::user::UserInformation;
use trustify_auth::authorizer::Authorizer;
use trustify_auth::Permission;
use trustify_common::model::Paginated;
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

#[utoipa::path(
    params(
        ("id", Path, description = "SBOM id to get packages for")
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
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let packages = fetch
        .fetch_sbom_packages(id.into_inner(), search, paginated, ())
        .await?;

    Ok(HttpResponse::Ok().json(packages))
}
