use actix_web::{get, HttpResponse, post, Responder, web};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Serialize, Deserialize)]
pub struct PackageParams {
    pub transitive: bool
}

#[utoipa::path(
    responses(
        (status = 200, description = "Dependencies"),
    ),
)]
#[get("package/{purl}/dependencies")]
pub async fn dependencies(state: web::Data<AppState>, purl: web::Path<String>, params: web::Query<PackageParams>) -> actix_web::Result<impl Responder> {
    if params.transitive {
        state.system.transitive_dependencies(
            &*purl
        ).await;
    } else {
        state.system.direct_dependencies(
            &*purl
        ).await;
    }

    Ok(HttpResponse::Ok().finish())
}

#[utoipa::path(
    responses(
        (status = 200, description = "Affected packages"),
    ),
)]
#[get("package/{purl}/dependents")]
pub async fn dependents(state: web::Data<AppState>, purl: web::Path<String>) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().finish())
}



#[utoipa::path(
    responses(
        (status = 200, description = "Affected packages"),
    ),
)]
#[get("package/{purl}/vulnerabilities")]
pub async fn vulnerabilities(state: web::Data<AppState>, purl: web::Path<String>, params: web::Query<PackageParams>) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().finish())
}