use crate::test::caller;
use actix_http::Request;
use actix_web::test::TestRequest;
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{call::CallService, subset::ContainsSubset, TrustifyContext};

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
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/BB@0.0.0" ]
        }]
    })));
    assert_eq!(&response["total"], 2);

    //should match a single component
    let uri = "/api/v2/analysis/root-component?q=BB";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/BB@0.0.0" ],
            "ancestors": [{
                "purl": [ "pkg:rpm/redhat/AA@0.0.0?arch=src" ]
            }]
        }]
    })));
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
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/B@0.0.0" ],
            "ancestors": [{
                "purl": [ "pkg:rpm/redhat/A@0.0.0?arch=src" ]
            }]
        }]
    })));
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

    let uri = format!(
        "/api/v2/analysis/root-component/{}",
        urlencoding::encode("pkg:rpm/redhat/B@0.0.0")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/B@0.0.0" ],
            "ancestors": [{
                "purl": [ "pkg:rpm/redhat/A@0.0.0?arch=src" ]
            }]
        }]
    })));
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

    let purl = "pkg:maven/net.spy/spymemcached@2.12.1?type=jar";
    let uri = "/api/v2/analysis/root-component?q=spymemcached";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [
            {
                "purl": [ purl ],
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.11.Final-redhat-00001",
                "ancestors": [{
                    "purl": [ "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom" ]
                }]
            },
            {
                "purl": [ purl ],
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.12.Final-redhat-00002",
                "ancestors": [{
                    "purl": [ "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.12.Final-redhat-00002?repository_url=https://maven.repository.redhat.com/ga/&type=pom" ]
                }]
            }
        ]
    })));
    assert_eq!(&response["total"], 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_status_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    // prime the graph hashmap
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

    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [
            {
                "purl": [ "pkg:rpm/redhat/A@0.0.0?arch=src" ],
                "deps": [
                    {
                        "purl": [ "pkg:rpm/redhat/B@0.0.0" ]
                    },
                    {
                        "purl": [ "pkg:rpm/redhat/EE@0.0.0?arch=src" ]
                    }
                ]
            },
            {
                "purl": [ "pkg:rpm/redhat/AA@0.0.0?arch=src" ],
                "deps": [
                    {
                        "purl": [ "pkg:rpm/redhat/BB@0.0.0" ],
                        "deps": [
                            {
                                "purl": [ "pkg:rpm/redhat/DD@0.0.0" ],
                                "deps": [{
                                    "name": "FF",
                                    "relationship": "ContainedBy",
                                    "purl": []
                                }]
                            },
                            {
                                "purl": [ "pkg:rpm/redhat/CC@0.0.0" ]
                            }
                        ]
                    }
                ]
            }
        ]
    })));

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
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/A@0.0.0?arch=src" ],
            "deps": [
                {
                    "purl": [ "pkg:rpm/redhat/EE@0.0.0?arch=src" ]
                },
                {
                    "purl": [ "pkg:rpm/redhat/B@0.0.0" ]
                }
            ]
        }]
    })));
    assert_eq!(&response["total"], 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_dep_by_purl_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let purl = "pkg:rpm/redhat/AA@0.0.0?arch=src";
    let uri = format!("/api/v2/analysis/dep/{}", urlencoding::encode(purl));
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ purl ],
            "deps": [{
                "purl": [ "pkg:rpm/redhat/BB@0.0.0" ]
            }]
        }]
    })));
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

    let purl = "pkg:maven/net.spy/spymemcached@2.12.1?type=jar";
    let uri = "/api/v2/analysis/dep?q=spymemcached";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [
            {
                "purl": [ purl ],
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.11.Final-redhat-00001"
            },
            {
                "purl": [ purl ],
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.12.Final-redhat-00002"
            }
        ]
    })));
    assert_eq!(&response["total"], 2);

    Ok(())
}

/// find a component by purl
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn quarkus_component_by_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let purl = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom";
    let uri = format!("/api/v2/analysis/component/{}", urlencoding::encode(purl));
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ purl ],
            "cpe": ["cpe:/a:redhat:quarkus:3.2:*:el8:*"]
        }]
    })));
    assert_eq!(&response["total"], 1);

    Ok(())
}

/// find a component by cpe
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn quarkus_component_by_cpe(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let cpe = "cpe:/a:redhat:quarkus:3.2:*:el8:*";
    let uri = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("cpe:/a:redhat:quarkus:3.2::el8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [
            {
                "purl": [ "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom" ],
                "cpe": [ cpe ]
            },
            {
                "purl": [ "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.12.Final-redhat-00002?repository_url=https://maven.repository.redhat.com/ga/&type=pom" ],
                "cpe": [ cpe ]
            }
        ]
    })));
    assert_eq!(&response["total"], 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_retrieve_query_params_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
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
    assert_eq!(&response["total"], 9);

    // negative test
    let uri =
        "/api/v2/analysis/root-component?q=sbom_id=urn:uuid:99999999-9999-9999-9999-999999999999";
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
async fn cdx_generated_from(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6.sbom.json"])
        .await?;

    // Find all deps of src rpm
    let src = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src";
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode(src)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    let deps = response.path(&format!(
        "$.items[?(@.node_id=='{src}')].descendants[?(@.relationship=='generated_from')]"
    ))?;
    assert_eq!(35, deps.as_array().unwrap().len());

    // Ensure binary rpm GeneratedFrom src rpm
    let x86 = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=x86_64";
    let uri = format!(
        "/api/v2/analysis/root-component/{}",
        urlencoding::encode(x86)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ x86 ],
            "ancestors": [{
                "relationship": "GeneratedFrom",
                "purl": [ src ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn spdx_generated_from(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/openssl-3.0.7-18.el9_2.spdx.json"])
        .await?;

    // Find all deps of src rpm
    let src = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src";
    let uri = format!("/api/v2/analysis/dep/{}", urlencoding::encode(src));
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{response:#?}");
    let deps = response
        .path("$.items[?(@.node_id=='SPDXRef-SRPM')].deps[?(@.relationship=='GeneratedFrom')]")?;
    assert_eq!(35, deps.as_array().unwrap().len());

    // Ensure binary rpm GeneratedFrom src rpm
    let x86 = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=x86_64";
    let uri = format!(
        "/api/v2/analysis/root-component/{}",
        urlencoding::encode(x86)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ x86 ],
            "ancestors": [{
                "relationship": "GeneratedFrom",
                "purl": [ src ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn cdx_variant_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["cyclonedx/66FF73123BB3489.json"])
        .await?;

    // Find all deps of parent
    let parent = "pkg:oci/ose-console@sha256:c2d69e860b7457eb42f550ba2559a0452ec3e5c9ff6521d758c186266247678e?arch=s390x&os=linux&tag=v4.14.0-202412110104.p0.g350e1ea.assembly.stream.el8";
    let child = "pkg:oci/openshift-ose-console@sha256:94a0d7feec34600a858c8e383ee0e8d5f4a077f6bbc327dcad8762acfcf40679";

    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode(parent)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ parent ],
            "descendants": [{
                "relationship": "variant",
                "purl": [ child ]
            }]
        }]
    })));

    // Ensure child is variant of src
    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(child)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ child ],
            "ancestors": [{
                "relationship": "variant",
                "purl": [ parent ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn spdx_variant_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["ubi9-9.2-755.1697625012.json"])
        .await?;

    let parents = [
            "pkg:oci/ubi9-container@sha256:d4c5d9c980678267b81c3c197a4a0dd206382111c912875a6cdffc6ca319b769?arch=aarch64&repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
            "pkg:oci/ubi9-container@sha256:204383c3d96c0e6c7154c91d07764f92035738dd67aa8896679f7feb73f66bfd?arch=x86_64&repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
            "pkg:oci/ubi9-container@sha256:721ca837c80c8b98752010a17ffccbdf17a0d260ddd916b7097f04187f6aa3a8?arch=s390x&repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
            "pkg:oci/ubi9-container@sha256:9a6092cdd8e7f4361ea3f508ae6d6d3d9dbb9458a921ab09e4cc006c0a7f0a61?arch=ppc64le&repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
        ];
    let child = "pkg:oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012";

    // Ensure variant relationships
    for parent in parents {
        let uri = format!(
            "/api/v2/analysis/component/{}?descendants=10",
            urlencoding::encode(parent)
        );
        let request: Request = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        tracing::debug!(test = "", "{response:#?}");

        assert!(response.contains_subset(json!({
            "items": [{
                "purl": [ parent ],
                "descendants": [{
                    "relationship": "variant",
                    "purl": [ child ]
                }]
            }]
        })));
    }

    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(child)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ child ],
            "ancestors": [
                {
                    "relationship": "variant",
                    "purl": [ parents[0] ]
                },
                {
                    "relationship": "variant",
                    "purl": [ parents[1] ]
                },
                {
                    "relationship": "variant",
                    "purl": [ parents[2] ]
                },
                {
                    "relationship": "variant",
                    "purl": [ parents[3] ]
                }
            ]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn cdx_ancestor_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6.sbom.json"])
        .await?;

    let parent = "pkg:generic/openssl@3.0.7?checksum=SHA-512:1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e&download_url=https://pkgs.devel.redhat.com/repo/openssl/openssl-3.0.7-hobbled.tar.gz/sha512/1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e/openssl-3.0.7-hobbled.tar.gz";
    let child = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src";

    // Ensure parent has ancestors that include the child
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode(parent)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ parent ],
            "descendants": [{
                "relationship": "ancestor_of",
                "purl": [ child ]
            }]
        }]
    })));

    // Ensure parent has deps that include the child
    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(child)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ child ],
            "ancestors": [{
                "relationship": "ancestor_of",
                "purl": [ parent ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn spdx_ancestor_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/1178.json"]).await?;

    let parent = "pkg:generic/upstream-component@0.0.0?arch=src";
    let child = "pkg:rpm/redhat/B@0.0.0";

    // Ensure parent has ancestors that include the child
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode(parent)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ parent ],
            "descendants": [{
                "relationship": "ancestor_of",
                "purl": [ child ]
            }]
        }]
    })));

    // Ensure child has ancestors that include the parent
    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(child)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ child ],
            "ancestors": [{
                "relationship": "ancestor_of",
                "purl": [ parent ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn spdx_package_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // test case for the simple case of "relationshipType": "PACKAGE_OF" spdx relationships:
    // https://github.com/trustification/trustify/issues/1140

    let app = caller(ctx).await?;
    ctx.ingest_document("spdx/SATELLITE-6.15-RHEL-8.json")
        .await?;

    let purl = "pkg:rpm/redhat/rubygem-google-cloud-compute@0.5.0-1.el8sat?arch=src";

    // Ensure child has an ancestor that includes it
    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(purl)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{}", serde_json::to_string_pretty(&response)?);

    assert!(response.contains_subset(json!({
        "items": [ {
            "ancestors": [ {
                "relationship": "packages",
                "name": "SATELLITE-6.15-RHEL-8",
                "version": "6.15",
            }]
        }]
    })));

    // Ensure the product contains the component
    let uri = format!(
        "/api/v2/analysis/component?q={}&descendants=10",
        urlencoding::encode("SATELLITE-6.15-RHEL-8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{}", serde_json::to_string_pretty(&response)?);

    assert!(response.contains_subset(json!({
        "items": [ {
            "descendants": [ {
                "relationship": "packages",
                "name": "rubygem-google-cloud-compute",
                "version": "0.5.0-1.el8sat"
            }]
        }]
    })));

    Ok(())
}
