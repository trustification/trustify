use super::service::AnalysisService;
use crate::Error;
use actix_web::{get, web, HttpResponse, Responder};
use std::str::FromStr;
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use utoipa::OpenApi;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let analysis = AnalysisService::new(db);

    config
        .app_data(web::Data::new(analysis))
        .service(search_component_root_components)
        .service(get_component_root_components)
        .service(analysis_status)
        .service(search_component_deps)
        .service(get_component_deps);
}
#[derive(OpenApi)]
#[openapi(
    paths(
        analysis_status,
        search_component_root_components,
        get_component_root_components,
        search_component_deps,
        get_component_deps,
    ),
    components(schemas(
        crate::model::PackageNode,
        crate::model::AnalysisStatus,
        crate::model::AncestorSummary,
        crate::model::AncNode,
        crate::model::DepSummary,
        crate::model::DepNode,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    context_path = "/api",
    tag = "analysis",
    operation_id = "status",
    responses(
        (status = 200, description = "Analysis status.", body = AnalysisStatus),
    ),
)]
#[get("/v1/analysis/status")]
pub async fn analysis_status(
    service: web::Data<AnalysisService>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.status(()).await?))
}

#[utoipa::path(
    context_path = "/api",
    tag = "analysis",
    operation_id = "searchComponentRootComponents",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Search component(s) and return their root components.", body = AncestorSummary),
    ),
)]
#[get("/v1/analysis/root-component")]
pub async fn search_component_root_components(
    service: web::Data<AnalysisService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve_root_components(search, paginated, ())
            .await?,
    ))
}

#[utoipa::path(
    context_path= "/api",
    tag = "analysis",
    operation_id = "getComponentRootComponents",
    params(
        ("key" = String, Path, description = "provide component name or URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Retrieve component(s) root components by name or pURL.", body = AncestorSummary),
    ),
)]
#[get("/v1/analysis/root-component/{key}")]
pub async fn get_component_root_components(
    service: web::Data<AnalysisService>,
    key: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    if key.starts_with("pkg://") {
        let purl: Purl = Purl::from_str(&key).map_err(Error::Purl)?;
        Ok(HttpResponse::Ok().json(
            service
                .retrieve_root_components_by_purl(purl, paginated, ())
                .await?,
        ))
    } else {
        Ok(HttpResponse::Ok().json(
            service
                .retrieve_root_components_by_name(key.to_string(), paginated, ())
                .await?,
        ))
    }
}

#[utoipa::path(
    context_path = "/api",
    tag = "analysis",
    operation_id = "searchComponentDeps",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Search component(s) and return their deps.", body = DepSummary),
    ),
)]
#[get("/v1/analysis/dep")]
pub async fn search_component_deps(
    service: web::Data<AnalysisService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.retrieve_deps(search, paginated, ()).await?))
}

#[utoipa::path(
    context_path= "/api",
    tag = "analysis",
    operation_id = "getComponentDeps",
    params(
        ("key" = String, Path, description = "provide component name or URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Retrieve component(s) dep components by name or pURL.", body = DepSummary),
    ),
)]
#[get("/v1/analysis/dep/{key}")]
pub async fn get_component_deps(
    service: web::Data<AnalysisService>,
    key: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    if key.starts_with("pkg://") {
        let purl: Purl = Purl::from_str(&key).map_err(Error::Purl)?;
        Ok(HttpResponse::Ok().json(service.retrieve_deps_by_purl(purl, paginated, ()).await?))
    } else {
        Ok(HttpResponse::Ok().json(
            service
                .retrieve_deps_by_name(key.to_string(), paginated, ())
                .await?,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::test::{caller, CallService};
    use actix_http::Request;
    use actix_web::test::TestRequest;
    use serde_json::Value;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_retrieve_analysis_endpoint(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        //should match multiple components
        let uri = "/api/v1/analysis/root-component?q=B";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        if response["items"][0]["purl"] == "pkg://rpm/redhat/BB@0.0.0"
            || response["items"][1]["purl"] == "pkg://rpm/redhat/BB@0.0.0"
        {
            assert_eq!(&response["total"], 2);
        } else {
            panic!("one of the items component should have matched.");
        }
        log::info!("{:?}", response);

        //should match a single component
        let uri = "/api/v1/analysis/root-component?q=BB";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        assert_eq!(response["items"][0]["purl"], "pkg://rpm/redhat/BB@0.0.0");
        assert_eq!(
            response["items"][0]["ancestors"][0]["purl"],
            "pkg://rpm/redhat/AA@0.0.0?arch=src"
        );
        Ok(assert_eq!(&response["total"], 1))
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_retrieve_by_name_analysis_endpoint(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v1/analysis/root-component/B";

        let request: Request = TestRequest::get().uri(uri).to_request();

        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(response["items"][0]["purl"], "pkg://rpm/redhat/B@0.0.0");
        assert_eq!(
            response["items"][0]["ancestors"][0]["purl"],
            "pkg://rpm/redhat/A@0.0.0?arch=src"
        );
        Ok(assert_eq!(&response["total"], 1))
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_retrieve_by_purl_analysis_endpoint(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v1/analysis/root-component/pkg%3A%2F%2Frpm%2Fredhat%2FB%400.0.0";

        let request: Request = TestRequest::get().uri(uri).to_request();

        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(response["items"][0]["purl"], "pkg://rpm/redhat/B@0.0.0");
        assert_eq!(
            response["items"][0]["ancestors"][0]["purl"],
            "pkg://rpm/redhat/A@0.0.0?arch=src"
        );
        Ok(assert_eq!(&response["total"], 1))
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_quarkus_retrieve_analysis_endpoint(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents([
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

        let uri = "/api/v1/analysis/root-component?q=spymemcached";

        let request: Request = TestRequest::get().uri(uri).to_request();

        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            "pkg://maven/net.spy/spymemcached@2.12.1?type=jar"
        );
        assert_eq!(
            response["items"][0]["document_id"],
            "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.11.Final-redhat-00001"
        );
        assert_eq!(
            response["items"][0]["ancestors"][0]["purl"],
            "pkg://maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?type=pom&repository_url=https://maven.repository.redhat.com/ga/"
        );

        Ok(assert_eq!(&response["total"], 2))
    }

    // TODO: this test passes when run individually.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    #[ignore]
    async fn test_status_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        //prime the graph hashmap
        let uri = "/api/v1/analysis/root-component?q=BB";
        let load1 = TestRequest::get().uri(uri).to_request();
        let _response: Value = app.call_and_read_body_json(load1).await;

        let uri = "/api/v1/analysis/status";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(response["sbom_count"], 1);
        assert_eq!(response["graph_count"], 1);

        // ingest duplicate sbom which has different date
        ctx.ingest_documents(["spdx/simple-dup.json"]).await?;

        let uri = "/api/v1/analysis/status";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(response["sbom_count"], 2);
        assert_eq!(response["graph_count"], 1);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_dep_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v1/analysis/dep?q=A";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            "pkg://rpm/redhat/A@0.0.0?arch=src"
        );
        assert_eq!(
            response["items"][0]["deps"][0]["purl"],
            "pkg://rpm/redhat/B@0.0.0"
        );

        Ok(assert_eq!(&response["total"], 2))
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_dep_by_name_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v1/analysis/dep/A";

        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            "pkg://rpm/redhat/A@0.0.0?arch=src"
        );
        assert_eq!(
            response["items"][0]["deps"][0]["purl"],
            "pkg://rpm/redhat/B@0.0.0"
        );

        Ok(assert_eq!(&response["total"], 1))
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_dep_by_purl_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v1/analysis/dep/pkg%3A%2F%2Frpm%2Fredhat%2FAA%400.0.0%3Farch%3Dsrc";

        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            "pkg://rpm/redhat/AA@0.0.0?arch=src"
        );
        assert_eq!(
            response["items"][0]["deps"][0]["purl"],
            "pkg://rpm/redhat/BB@0.0.0"
        );
        Ok(assert_eq!(&response["total"], 1))
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_quarkus_dep_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents([
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

        let uri = "/api/v1/analysis/dep?q=spymemcached";

        let request: Request = TestRequest::get().uri(uri).to_request();

        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            "pkg://maven/net.spy/spymemcached@2.12.1?type=jar"
        );
        Ok(assert_eq!(&response["total"], 2))
    }
}
