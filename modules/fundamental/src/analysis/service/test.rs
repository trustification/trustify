use super::*;

use crate::analysis::service::AnalysisService;
use test_context::test_context;
use test_log::test;
use trustify_common::model::Paginated;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(ctx.db.clone());

    let analysis_graph = service
        .retrieve_root_components(Query::q("DD"), Paginated::default(), ())
        .await
        .unwrap();
    assert_eq!(analysis_graph.total, 1);
    assert_eq!(
        analysis_graph.items.last().unwrap().ancestors,
        [
            PackageNode {
                purl: "pkg://rpm/redhat/BB@0.0.0".to_string(),
                name: "BB".to_string(),
                published: "1970-01-01 13:30:00+00".to_string(),
            },
            PackageNode {
                purl: "pkg://rpm/redhat/AA@0.0.0".to_string(),
                name: "AA".to_string(),
                published: "1970-01-01 13:30:00+00".to_string(),
            },
            PackageNode {
                purl: "pkg://rpm/redhat/DD@0.0.0".to_string(),
                name: "DD".to_string(),
                published: "1970-01-01 13:30:00+00".to_string(),
            }
        ]
    );

    let analysis_graph = service
        .retrieve_root_components(Query::q("EE"), Paginated::default(), ())
        .await
        .unwrap();
    Ok(assert_eq!(analysis_graph.total, 0)) //TODO: should this not match with no root_components ?
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_name_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(ctx.db.clone());

    let analysis_graph = service
        .retrieve_root_components_by_name("B".to_string(), Paginated::default(), ())
        .await
        .unwrap();
    Ok(assert_eq!(
        analysis_graph.items.last().unwrap().ancestors,
        [
            PackageNode {
                purl: "pkg://rpm/redhat/B@0.0.0".to_string(),
                name: "B".to_string(),
                published: "1970-01-01 13:30:00+00".to_string(),
            },
            PackageNode {
                purl: "pkg://rpm/redhat/A@0.0.0".to_string(),
                name: "A".to_string(),
                published: "1970-01-01 13:30:00+00".to_string(),
            }
        ]
    ))
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_purl_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(ctx.db.clone());

    let component_purl: Purl = Purl::from_str("pkg://rpm/redhat/B@0.0.0").map_err(Error::Purl)?;

    let analysis_graph = service
        .retrieve_root_components_by_purl(component_purl, Paginated::default(), ())
        .await
        .unwrap();
    //TODO: add negative tests
    Ok(assert_eq!(
        analysis_graph.items.last().unwrap().ancestors,
        [
            PackageNode {
                purl: "pkg://rpm/redhat/B@0.0.0".to_string(),
                name: "B".to_string(),
                published: "1970-01-01 13:30:00+00".to_string(),
            },
            PackageNode {
                purl: "pkg://rpm/redhat/A@0.0.0".to_string(),
                name: "A".to_string(),
                published: "1970-01-01 13:30:00+00".to_string(),
            }
        ]
    ))
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_quarkus_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let service = AnalysisService::new(ctx.db.clone());

    let analysis_graph = service
        .retrieve_root_components(Query::q("spymemcached"), Paginated::default(), ())
        .await
        .unwrap();

    assert_eq!(
        analysis_graph.items.last().unwrap().ancestors,
        [PackageNode {
            purl: "pkg://maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?type=pom&repository_url=https://maven.repository.redhat.com/ga/".to_string(),
            name: "quarkus-bom".to_string(),
            published: "2024-05-28 09:26:01+00".to_string(),
        },
         PackageNode {
            purl: "pkg://maven/net.spy/spymemcached@2.12.1?type=jar".to_string(),
            name: "spymemcached".to_string(),
            published: "2024-05-28 09:26:01+00".to_string(),
         },
         PackageNode {
            purl: "pkg://maven/com.redhat.quarkus.platform/quarkus-bom@3.2.12.Final-redhat-00002?type=pom&repository_url=https://maven.repository.redhat.com/ga/".to_string(),
            name: "quarkus-bom".to_string(),
            published: "2024-07-05 09:40:48+00".to_string(),
         }]
    );
    Ok(assert_eq!(analysis_graph.total, 1))
}
