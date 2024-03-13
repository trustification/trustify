use actix_web::{get, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use trustify_graph::db::Transactional;
use trustify_auth::authenticator::user::UserInformation;
use trustify_auth::authorizer::Authorizer;
use trustify_auth::Permission;

use trustify_common::purl::Purl;

use crate::server::Error;
use crate::AppState;

#[derive(Serialize, Deserialize)]
pub struct PackageParams {
    pub transitive: Option<bool>,
}

#[utoipa::path(
    responses(
        (status = 200, description = "Dependencies"),
    ),
)]
#[get("package/{purl}/dependencies")]
pub async fn dependencies(
    state: web::Data<AppState>,
    purl: web::Path<String>,
    params: web::Query<PackageParams>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let purl: Purl = Purl::from(&*purl);

    /*
    if matches!(params.transitive, Some(true)) {
        let tree = state
            .graph
            .transitive_package_dependencies(purl.clone(), Transactional::None)
            .await
            .map_err(Error::from)?;
        Ok(HttpResponse::Ok().json(tree))
    } else {
        let dependencies = state
            .graph
            .direct_dependencies(purl.clone(), Transactional::None)
            .await
            .map_err(Error::from)?;
        Ok(HttpResponse::Ok().json(dependencies))
    }

     */

    Ok(HttpResponse::Ok().finish())
}

#[utoipa::path(
    responses(
        (status = 200, description = "Affected packages"),
    ),
)]
#[get("package/{purl}/dependents")]
pub async fn dependents(
    state: web::Data<AppState>,
    purl: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().finish())
}

#[utoipa::path(
    responses(
        (status = 200, description = "Affected packages"),
    ),
)]
#[get("package/{purl}/variants")]
pub async fn variants(
    state: web::Data<AppState>,
    purl: web::Path<String>,
) -> Result<impl Responder, Error> {
    let purl: Purl = Purl::from_str(&purl)?;

    /*
    let response = state
        .graph
        .package_variants(purl)
        .await
        .map_err(Error::System)?;
    Ok(HttpResponse::Ok().json(response))

     */
    Ok(HttpResponse::Ok().finish())
}

#[utoipa::path(
    responses(
        (status = 200, description = "Affected packages"),
    ),
)]
#[get("package/{purl}/vulnerabilities")]
pub async fn vulnerabilities(
    state: web::Data<AppState>,
    purl: web::Path<String>,
    params: web::Query<PackageParams>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().finish())
}

/*
#[cfg(test)]
mod tests {
    use crate::test_util::bootstrap_system;
    use crate::{configure, AppState};
    use actix_web::test::TestRequest;
    use actix_web::web::Data;
    use actix_web::{test, App};
    use huevos_api::db::Transactional;
    use huevos_common::package::PackageTree;
    use huevos_common::purl::Purl;
    use std::sync::Arc;
    use url_escape::encode_component;

    #[actix_web::test]
    async fn direct_dependencies() -> Result<(), anyhow::Error> {
        let state = Arc::new(AppState {
            graph: bootstrap_system("package-dependencies").await?,
        });

        let sbom = state
            .graph
            .ingest_sbom("http://test.com/package-dependencies", "7")
            .await?;

        state
            .graph
            .ingest_package_dependency(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                "pkg:maven/com.test/package-ab@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        state
            .graph
            .ingest_package_dependency(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        state
            .graph
            .ingest_package_dependency(
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                "pkg:maven/com.test/package-acd@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        state
            .graph
            .ingest_package_dependency(
                "pkg:maven/com.test/package-ab@1.0?type=jar",
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        let app = test::init_service(
            App::new()
                .app_data(Data::from(state.clone()))
                .configure(configure),
        )
        .await;

        let uri = format!(
            "/package/{}/dependencies",
            encode_component("pkg://maven/com.test/package-a@1.0?type=jar")
        );

        let request = TestRequest::get().uri(&uri).to_request();

        let response: Vec<Purl> = test::call_and_read_body_json(&app, request).await;

        assert_eq!(2, response.len());
        assert!(response.contains(&"pkg://maven/com.test/package-ab@1.0?type=jar".into()));
        assert!(response.contains(&"pkg://maven/com.test/package-ac@1.0?type=jar".into()));

        Ok(())
    }

    #[actix_web::test]
    async fn transitive_dependencies() -> Result<(), anyhow::Error> {
        let state = Arc::new(AppState {
            graph: bootstrap_system("package-transitive-dependencies").await?,
        });

        let sbom = state
            .graph
            .ingest_sbom("http://test.com/package-transitive-dependencies", "8")
            .await?;

        state
            .graph
            .ingest_package_dependency(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                "pkg:maven/com.test/package-ab@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        state
            .graph
            .ingest_package_dependency(
                "pkg:maven/com.test/package-a@1.0?type=jar",
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        state
            .graph
            .ingest_package_dependency(
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                "pkg:maven/com.test/package-acd@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        state
            .graph
            .ingest_package_dependency(
                "pkg:maven/com.test/package-ab@1.0?type=jar",
                "pkg:maven/com.test/package-ac@1.0?type=jar",
                &sbom,
                Transactional::None,
            )
            .await?;

        let app = test::init_service(
            App::new()
                .app_data(Data::from(state.clone()))
                .configure(configure),
        )
        .await;

        let uri = format!(
            "/package/{}/dependencies?transitive=true",
            encode_component("pkg://maven/com.test/package-a@1.0?type=jar")
        );

        let request = TestRequest::get().uri(&uri).to_request();

        let response: PackageTree = test::call_and_read_body_json(&app, request).await;

        assert_eq!(
            Purl::from("pkg://maven/com.test/package-a@1.0?type=jar"),
            response.purl
        );

        assert_eq!(2, response.dependencies.len());

        Ok(())
    }


    #[actix_web::test]
    async fn variants() -> Result<(), anyhow::Error> {
        let state = Arc::new(AppState {
            graph: bootstrap_system("package-variants").await?,
        });

        state
            .graph
            .ingest_package("pkg://maven/com.foo/test@1.2", Transactional::None)
            .await?;
        state
            .graph
            .ingest_package("pkg://maven/com.foo/test@1.3", Transactional::None)
            .await?;
        state
            .graph
            .ingest_package("pkg://maven/com.foo/test@1.4", Transactional::None)
            .await?;
        state
            .graph
            .ingest_package("pkg://maven/com.foo/test@1.5", Transactional::None)
            .await?;
        state
            .graph
            .ingest_package("pkg://maven/com.foo/test@1.6", Transactional::None)
            .await?;
        state
            .graph
            .ingest_package("pkg://maven/com.foo/test@1.6?foo=bar", Transactional::None)
            .await?;

        let app = test::init_service(
            App::new()
                .app_data(Data::from(state.clone()))
                .configure(configure),
        )
        .await;

        let uri = format!(
            "/package/{}/variants",
            encode_component("pkg://maven/com.foo/test")
        );

        let request = TestRequest::get().uri(&uri).to_request();

        let response: Vec<String> = test::call_and_read_body_json(&app, request).await;

        assert_eq!(6, response.len());
        assert!(response.contains(&"pkg://maven/com.foo/test@1.2".into()));
        assert!(response.contains(&"pkg://maven/com.foo/test@1.3".into()));
        assert!(response.contains(&"pkg://maven/com.foo/test@1.4".into()));
        assert!(response.contains(&"pkg://maven/com.foo/test@1.5".into()));
        assert!(response.contains(&"pkg://maven/com.foo/test@1.6".into()));
        assert!(response.contains(&"pkg://maven/com.foo/test@1.6?foo=bar".into()));

        Ok(())
    }
}


 */
