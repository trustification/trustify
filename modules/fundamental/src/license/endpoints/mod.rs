use crate::license::get_sanitize_filename;
use crate::license::service::license_export::LicenseExporter;
use crate::{
    Error,
    license::{
        endpoints::spdx::{get_spdx_license, list_spdx_licenses},
        // model::LicenseSummary,
        service::LicenseService,
    },
};
use actix_web::{HttpResponse, Responder, get, web};
use std::str::FromStr;
use trustify_common::{db::Database, id::Id};

pub mod spdx;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let license_service = LicenseService::new(db);

    config
        .app_data(web::Data::new(license_service))
        .service(list_spdx_licenses)
        .service(get_spdx_license)
        // .service(list_licenses)
        // .service(get_license)
        // .service(get_license_purls)
        .service(get_license_export);
}

// #[utoipa::path(
//     tag = "license",
//     operation_id = "listLicenses",
//     params(
//         Query,
//         Paginated,
//     ),
//     responses(
//         (status = 200, description = "Matching licenses", body = PaginatedResults<LicenseSummary>),
//     ),
// )]
// #[get("/v2/license")]
// /// List licenses
// pub async fn list_licenses(
//     state: web::Data<LicenseService>,
//     web::Query(search): web::Query<Query>,
//     web::Query(paginated): web::Query<Paginated>,
// ) -> actix_web::Result<impl Responder> {
//     Ok(HttpResponse::Ok().json(state.list_licenses(search, paginated).await?))
// }

// #[utoipa::path(
//     tag = "license",
//     operation_id = "getLicenses",
//     responses(
//         (status = 200, description = "The license", body = LicenseSummary),
//     ),
// )]
// #[get("/v2/license/{uuid}")]
// /// Retrieve license details
// pub async fn get_license(
//     state: web::Data<LicenseService>,
//     uuid: web::Path<Uuid>,
// ) -> actix_web::Result<impl Responder> {
//     Ok(HttpResponse::Ok().json(state.get_license(*uuid).await?))
// }

// #[utoipa::path(
//     tag = "license",
//     operation_id = "getLicensePurls",
//     params(
//         Query,
//         Paginated,
//     ),
//     responses(
//         (status = 200, description = "The versioned pURLs allowing the license", body = LicenseSummary),
//     ),
// )]
// #[get("/v2/license/{uuid}/purl")]
// /// Retrieve pURLs covered by a license
// pub async fn get_license_purls(
//     state: web::Data<LicenseService>,
//     uuid: web::Path<String>,
//     web::Query(search): web::Query<Query>,
//     web::Query(paginated): web::Query<Paginated>,
// ) -> actix_web::Result<impl Responder> {
//     let uuid = Uuid::from_str(&uuid).map_err(|e| Error::IdKey(IdError::InvalidUuid(e)))?;
//     Ok(HttpResponse::Ok().json(state.get_license_purls(uuid, search, paginated).await?))
// }

#[utoipa::path(
    tag = "sbom",
    operation_id = "getLicenseExport",
    params(
        ("id" = String, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
    (status = 200, description = "license zip file", body = Vec<u8>),
    (status = 404, description = "The document could not be found"),
    ),
)]
#[get("/v2/sbom/{id}/license-export")]
pub async fn get_license_export(
    fetcher: web::Data<LicenseService>,
    db: web::Data<Database>,
    id: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    let id = Id::from_str(&id).map_err(Error::IdKey)?;

    let (sbom_license_list, sbom_license_info_list, sbom_name_version_group) =
        fetcher.license_export(id, db.as_ref()).await?;
    if let Some(name_group_version) = sbom_name_version_group.clone() {
        let exporter = LicenseExporter::new(
            name_group_version.sbom_name.clone(),
            name_group_version.sbom_group.clone(),
            name_group_version.sbom_version.clone(),
            sbom_license_list,
            sbom_license_info_list,
        );
        let zip = exporter.generate()?;

        Ok(HttpResponse::Ok()
            .content_type("application/gzip")
            .append_header((
                "Content-Disposition",
                format!(
                    "attachment; filename=\"{}_licenses.tar.gz\"",
                    get_sanitize_filename(name_group_version.sbom_name.clone())
                ),
            ))
            .body(zip))
    } else {
        Ok(HttpResponse::NotFound().into())
    }
}
#[cfg(test)]
mod test;
