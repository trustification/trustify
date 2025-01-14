use super::service::AnalysisService;
use crate::{
    model::{AnalysisStatus, AncestorSummary, DepSummary},
    Error,
};
use actix_web::{get, web, HttpResponse, Responder};
use std::str::FromStr;
use trustify_auth::{
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
    Permission, ReadSbom,
};
use trustify_common::{db::query::Query, db::Database, model::Paginated, purl::Purl};

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let analysis = AnalysisService::new();

    config
        .app_data(web::Data::new(analysis))
        .app_data(web::Data::new(db))
        .service(search_component_root_components)
        .service(get_component_root_components)
        .service(analysis_status)
        .service(search_component_deps)
        .service(get_component_deps);
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "status",
    responses(
        (status = 200, description = "Analysis status.", body = AnalysisStatus),
    ),
)]
#[get("/v2/analysis/status")]
pub async fn analysis_status(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    user: UserInformation,
    authorizer: web::Data<Authorizer>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;
    Ok(HttpResponse::Ok().json(service.status(db.as_ref()).await?))
}

#[utoipa::path(
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
#[get("/v2/analysis/root-component")]
pub async fn search_component_root_components(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve_root_components(&search, paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "getComponentRootComponents",
    params(
        ("key" = String, Path, description = "provide component name or URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Retrieve component(s) root components by name or pURL.", body = AncestorSummary),
    ),
)]
#[get("/v2/analysis/root-component/{key}")]
pub async fn get_component_root_components(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    if key.starts_with("pkg:") {
        let purl: Purl = Purl::from_str(&key).map_err(Error::Purl)?;
        Ok(HttpResponse::Ok().json(
            service
                .retrieve_root_components(&purl, paginated, db.as_ref())
                .await?,
        ))
    } else {
        Ok(HttpResponse::Ok().json(
            service
                .retrieve_root_components(&key.to_string(), paginated, db.as_ref())
                .await?,
        ))
    }
}

#[utoipa::path(
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
#[get("/v2/analysis/dep")]
pub async fn search_component_deps(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve_deps(&search, paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "getComponentDeps",
    params(
        ("key" = String, Path, description = "provide component name or URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Retrieve component(s) dep components by name or pURL.", body = DepSummary),
    ),
)]
#[get("/v2/analysis/dep/{key}")]
pub async fn get_component_deps(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    if key.starts_with("pkg:") {
        let purl: Purl = Purl::from_str(&key).map_err(Error::Purl)?;
        Ok(HttpResponse::Ok().json(service.retrieve_deps(&purl, paginated, db.as_ref()).await?))
    } else {
        Ok(HttpResponse::Ok().json(
            service
                .retrieve_deps(&key.to_string(), paginated, db.as_ref())
                .await?,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::test::caller;
    use actix_http::Request;
    use actix_web::test::TestRequest;
    use serde_json::Value;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::{call::CallService, TrustifyContext};

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_retrieve_analysis_endpoint(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        //should match multiple components
        let uri = "/api/v2/analysis/root-component?q=B";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        if response["items"][0]["purl"]
            .as_array()
            .unwrap()
            .contains(&Value::from("pkg:rpm/redhat/BB@0.0.0"))
            || response["items"][1]["purl"]
                .as_array()
                .unwrap()
                .contains(&Value::from("pkg:rpm/redhat/BB@0.0.0"))
        {
            assert_eq!(&response["total"], 2);
        } else {
            panic!("one of the items component should have matched.");
        }
        log::info!("{:?}", response);

        //should match a single component
        let uri = "/api/v2/analysis/root-component?q=BB";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        assert_eq!(
            response["items"][0]["purl"],
            Value::from(["pkg:rpm/redhat/BB@0.0.0"])
        );
        assert_eq!(
            response["items"][0]["ancestors"][0]["purl"],
            Value::from(["pkg:rpm/redhat/AA@0.0.0?arch=src"])
        );

        assert_eq!(&response["total"], 1);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_retrieve_by_name_analysis_endpoint(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v2/analysis/root-component/B";

        let request: Request = TestRequest::get().uri(uri).to_request();

        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            Value::from(["pkg:rpm/redhat/B@0.0.0"])
        );
        assert_eq!(
            response["items"][0]["ancestors"][0]["purl"],
            Value::from(["pkg:rpm/redhat/A@0.0.0?arch=src"])
        );
        assert_eq!(&response["total"], 1);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_retrieve_by_purl_analysis_endpoint(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v2/analysis/root-component/pkg%3A%2F%2Frpm%2Fredhat%2FB%400.0.0";

        let request: Request = TestRequest::get().uri(uri).to_request();

        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            Value::from(["pkg:rpm/redhat/B@0.0.0"])
        );
        assert_eq!(
            response["items"][0]["ancestors"][0]["purl"],
            Value::from(["pkg:rpm/redhat/A@0.0.0?arch=src"])
        );
        assert_eq!(&response["total"], 1);
        Ok(())
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

        let uri = "/api/v2/analysis/root-component?q=spymemcached";

        let request: Request = TestRequest::get().uri(uri).to_request();

        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            Value::from(["pkg:maven/net.spy/spymemcached@2.12.1?type=jar"])
        );
        assert_eq!(
            response["items"][0]["document_id"],
            "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.11.Final-redhat-00001"
        );
        assert_eq!(
            response["items"][0]["ancestors"][0]["purl"],
            Value::from(["pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https%3A%2F%2Fmaven%2Erepository%2Eredhat%2Ecom%2Fga%2F&type=pom"])
        );

        assert_eq!(&response["total"], 2);
        Ok(())
    }

    // TODO: this test passes when run individually.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    #[ignore]
    async fn test_status_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        //prime the graph hashmap
        let uri = "/api/v2/analysis/root-component?q=BB";
        let load1 = TestRequest::get().uri(uri).to_request();
        let _response: Value = app.call_and_read_body_json(load1).await;

        let uri = "/api/v2/analysis/status";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(response["sbom_count"], 1);
        assert_eq!(response["graph_count"], 1);

        // ingest duplicate sbom which has different date
        ctx.ingest_documents(["spdx/simple-dup.json"]).await?;

        let uri = "/api/v2/analysis/status";
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

        let uri = "/api/v2/analysis/dep?q=A";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        println!("Result: {response:#?}");

        assert_eq!(
            response["items"][0]["purl"],
            Value::from(["pkg:rpm/redhat/A@0.0.0?arch=src"]),
        );
        assert_eq!(
            response["items"][0]["deps"][0]["purl"],
            Value::from(["pkg:rpm/redhat/EE@0.0.0?arch=src"]),
        );
        assert_eq!(
            response["items"][0]["deps"][1]["purl"],
            Value::from(["pkg:rpm/redhat/B@0.0.0"]),
        );

        assert_eq!(&response["total"], 2);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_dep_by_name_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v2/analysis/dep/A";

        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            Value::from(["pkg:rpm/redhat/A@0.0.0?arch=src"]),
        );
        assert_eq!(
            response["items"][0]["deps"][0]["purl"],
            Value::from(["pkg:rpm/redhat/EE@0.0.0?arch=src"]),
        );
        assert_eq!(
            response["items"][0]["deps"][1]["purl"],
            Value::from(["pkg:rpm/redhat/B@0.0.0"]),
        );

        assert_eq!(&response["total"], 1);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_simple_dep_by_purl_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let uri = "/api/v2/analysis/dep/pkg%3A%2F%2Frpm%2Fredhat%2FAA%400.0.0%3Farch%3Dsrc";

        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            Value::from(["pkg:rpm/redhat/AA@0.0.0?arch=src"]),
        );
        assert_eq!(
            response["items"][0]["deps"][0]["purl"],
            Value::from(["pkg:rpm/redhat/BB@0.0.0"]),
        );
        assert_eq!(&response["total"], 1);
        Ok(())
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

        let uri = "/api/v2/analysis/dep?q=spymemcached";

        let request: Request = TestRequest::get().uri(uri).to_request();

        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(
            response["items"][0]["purl"],
            Value::from(["pkg:maven/net.spy/spymemcached@2.12.1?type=jar"]),
        );
        assert_eq!(&response["total"], 2);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn test_retrieve_query_params_endpoint(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        // filter on node_id
        let uri = "/api/v2/analysis/dep?q=node_id%3DSPDXRef-A";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        assert_eq!(response["items"][0]["name"], "A");
        assert_eq!(&response["total"], 1);

        // filter on node_id
        let uri = "/api/v2/analysis/root-component?q=node_id%3DSPDXRef-B";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        assert_eq!(response["items"][0]["name"], "B");
        assert_eq!(&response["total"], 1);

        // filter on node_id & name
        let uri = "/api/v2/analysis/root-component?q=node_id%3DSPDXRef-B%26name%3DB";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        assert_eq!(response["items"][0]["name"], "B");
        assert_eq!(&response["total"], 1);

        // filter on sbom_id (which has urn:uuid: prefix)
        let sbom_id = response["items"][0]["sbom_id"].as_str().unwrap();
        let uri = format!("/api/v2/analysis/root-component?q=sbom_id={}", sbom_id);
        let request: Request = TestRequest::get().uri(uri.clone().as_str()).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        assert_eq!(&response["total"], 8);

        // negative test
        let uri = "/api/v2/analysis/root-component?q=sbom_id=urn:uuid:99999999-9999-9999-9999-999999999999";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        assert_eq!(&response["total"], 0);

        // negative test
        let uri = "/api/v2/analysis/root-component?q=node_id%3DSPDXRef-B%26name%3DA";
        let request: Request = TestRequest::get().uri(uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;

        assert_eq!(&response["total"], 0);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn issue_tc_2050(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let app = caller(ctx).await?;
        ctx.ingest_documents(["cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6.sbom.json"])
            .await?;

        // Find all deps of src rpm
        let src = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src";
        let uri = format!("/api/v2/analysis/dep/{}", urlencoding::encode(src));
        let request: Request = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        log::debug!("{response:#?}");
        assert_eq!(35, response["items"][0]["deps"].as_array().unwrap().len());

        // Ensure binary rpm GeneratedFrom src rpm
        let x86 = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=x86_64";
        let uri = format!(
            "/api/v2/analysis/root-component/{}",
            urlencoding::encode(x86)
        );
        let request: Request = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        log::debug!("{response:#?}");
        assert_eq!(
            "GeneratedFrom",
            response["items"][0]["ancestors"][0]["relationship"]
        );
        assert_eq!(src, response["items"][0]["ancestors"][0]["purl"]);

        Ok(())
    }
}
