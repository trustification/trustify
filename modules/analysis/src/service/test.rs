use super::*;
use crate::test::*;
use std::{str::FromStr, time::SystemTime};
use test_context::test_context;
use test_log::test;
use trustify_common::{
    cpe::Cpe, db::query::Query, model::Paginated, purl::Purl, sbom::spdx::fix_license,
};
use trustify_test_context::{document, spdx::fix_spdx_rels, TrustifyContext};

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json", "spdx/simple.json"])
        .await?; //double ingestion intended

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_root_components(&Query::q("DD"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(
        analysis_graph
            .items
            .last()
            .unwrap()
            .ancestors
            .last()
            .unwrap()
            .purl,
        vec![Purl::from_str("pkg:rpm/redhat/AA@0.0.0?arch=src")?]
    );
    assert_eq!(
        analysis_graph
            .items
            .last()
            .unwrap()
            .ancestors
            .last()
            .unwrap()
            .node_id,
        "SPDXRef-AA".to_string()
    );
    assert_eq!(analysis_graph.total, 1);

    // ensure we set implicit relationship on component with no defined relationships
    let analysis_graph = service
        .retrieve_root_components(&Query::q("EE"), Paginated::default(), &ctx.db)
        .await?;
    assert_eq!(analysis_graph.total, 1);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_analysis_cyclonedx_service(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json", "cyclonedx/simple.json"])
        .await?; //double ingestion intended

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_root_components(&Query::q("DD"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(
        analysis_graph
            .items
            .last()
            .unwrap()
            .ancestors
            .last()
            .unwrap()
            .purl,
        vec![Purl::from_str("pkg:rpm/redhat/AA@0.0.0?arch=src")?]
    );
    let node = analysis_graph
        .items
        .last()
        .unwrap()
        .ancestors
        .last()
        .unwrap();
    assert_eq!(node.node_id, "aa".to_string());
    assert_eq!(node.name, "AA".to_string());
    assert_eq!(analysis_graph.total, 1);

    // ensure we set implicit relationship on component with no defined relationships
    let analysis_graph = service
        .retrieve_root_components(&Query::q("EE"), Paginated::default(), &ctx.db)
        .await?;
    assert_eq!(analysis_graph.total, 1);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_name_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_root_components("B", Paginated::default(), &ctx.db)
        .await?;

    assert_ancestors(&analysis_graph.items, |ancestors| {
        assert_eq!(
            ancestors,
            &[&[
                Node {
                    id: "SPDXRef-A",
                    name: "A",
                    version: "1",
                    cpes: &["cpe:/a:redhat:simple:1:*:el9:*"],
                    purls: &["pkg:rpm/redhat/A@0.0.0?arch=src"],
                },
                Node {
                    id: "SPDXRef-DOCUMENT",
                    name: "simple",
                    version: "",
                    cpes: &[],
                    purls: &[],
                },
            ]]
        );
    });

    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_purl_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new();

    let component_purl: Purl = Purl::from_str("pkg:rpm/redhat/B@0.0.0").map_err(Error::Purl)?;

    let analysis_graph = service
        .retrieve_root_components(&component_purl, Paginated::default(), &ctx.db)
        .await?;

    assert_ancestors(&analysis_graph.items, |ancestors| {
        assert_eq!(
            ancestors,
            [[
                Node {
                    id: "SPDXRef-A",
                    name: "A",
                    version: "1",
                    purls: &["pkg:rpm/redhat/A@0.0.0?arch=src"],
                    cpes: &["cpe:/a:redhat:simple:1:*:el9:*"],
                },
                Node {
                    id: "SPDXRef-DOCUMENT",
                    name: "simple",
                    version: "",
                    cpes: &[],
                    purls: &[],
                }
            ]]
        );
    });

    assert_eq!(analysis_graph.total, 1);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_quarkus_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_root_components(&Query::q("spymemcached"), Paginated::default(), &ctx.db)
        .await?;

    assert_ancestors(&analysis_graph.items, |ancestors| {
        assert!(
            matches!(ancestors, [
                [..],
                [
                   Node {
                       id: "SPDXRef-DOCUMENT",
                       name: "quarkus-bom-3.2.12.Final-redhat-00002",
                       version: "",
                       ..
                   },
                   Node {
                       id: "SPDXRef-e24fec28-1001-499c-827f-2e2e5f2671b5",
                       name: "quarkus-bom",
                       version: "3.2.12.Final-redhat-00002",
                       cpes: [
                           "cpe:/a:redhat:quarkus:3.2:*:el8:*",
                       ],
                       purls: [
                           "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.12.Final-redhat-00002?repository_url=https://maven.repository.redhat.com/ga/&type=pom"
                       ],
                   },
                ]
            ]),
            "must match: {ancestors:#?}"
        );
    });

    assert_eq!(analysis_graph.total, 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_status_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new();
    let _load_all_graphs = service.load_all_graphs(&ctx.db).await;
    let analysis_status = service.status(&ctx.db).await?;

    assert_eq!(analysis_status.sbom_count, 1);
    assert_eq!(analysis_status.graph_count, 1);

    let _clear_all_graphs = service.clear_all_graphs();

    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let analysis_status = service.status(&ctx.db).await?;

    assert_eq!(analysis_status.sbom_count, 3);
    assert_eq!(analysis_status.graph_count, 0);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_deps(&Query::q("AA"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(analysis_graph.total, 1);

    // ensure we set implicit relationship on component with no defined relationships
    let analysis_graph = service
        .retrieve_root_components(&Query::q("EE"), Paginated::default(), &ctx.db)
        .await?;
    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_deps_cyclonedx_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_deps(&Query::q("AA"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(analysis_graph.total, 1);

    // ensure we set implicit relationship on component with no defined relationships
    let analysis_graph = service
        .retrieve_root_components(&Query::q("EE"), Paginated::default(), &ctx.db)
        .await?;
    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_name_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_deps("A", Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(analysis_graph.items.len(), 1);
    assert_eq!(analysis_graph.total, 1);

    assert_eq!(
        analysis_graph.items[0].purl,
        vec![Purl::from_str("pkg:rpm/redhat/A@0.0.0?arch=src")?]
    );
    assert_eq!(
        analysis_graph.items[0].cpe,
        vec![Cpe::from_str("cpe:/a:redhat:simple:1::el9")?]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_purl_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new();

    let component_purl: Purl =
        Purl::from_str("pkg:rpm/redhat/AA@0.0.0?arch=src").map_err(Error::Purl)?;

    let analysis_graph = service
        .retrieve_deps(&component_purl, Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(
        analysis_graph.items[0].purl,
        vec![Purl::from_str("pkg:rpm/redhat/AA@0.0.0?arch=src")?]
    );

    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_quarkus_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_deps(&Query::q("spymemcached"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(analysis_graph.total, 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_circular_deps_cyclonedx_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/cyclonedx-circular.json"])
        .await?;

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_deps("junit-bom", Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_circular_deps_spdx_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/loop.json"]).await?;

    let service = AnalysisService::new();

    let analysis_graph = service
        .retrieve_deps("A", Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_retrieve_all_sbom_roots_by_name(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
        .await?;

    let service = AnalysisService::new();
    let component_name = "quarkus-vertx-http".to_string();

    let analysis_graph = service
        .retrieve_root_components(&Query::q(&component_name), Paginated::default(), &ctx.db)
        .await?;

    log::debug!("Result: {analysis_graph:#?}");

    let sbom_id = analysis_graph
        .items
        .last()
        .unwrap()
        .sbom_id
        .parse::<Uuid>()?;

    let roots = service
        .retrieve_all_sbom_roots_by_name(sbom_id, component_name, &ctx.db)
        .await?;

    assert_eq!(
        roots.last().unwrap().name,
        "quarkus-bom-3.2.11.Final-redhat-00001"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn load_performance(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let (spdx, _) =
        document::<serde_json::Value>("openshift-container-storage-4.8.z.json.xz").await?;
    let (spdx, _) = fix_license(&(), spdx);
    let spdx = fix_spdx_rels(serde_json::from_value(spdx)?);

    log::info!("Start ingestion");

    ctx.ingest_json(spdx).await?;

    log::info!("Start populating graph");

    let start = SystemTime::now();
    let service = AnalysisService::new();
    service.load_all_graphs(&ctx.db).await?;

    log::info!(
        "Loading took: {}",
        humantime::format_duration(start.elapsed()?)
    );

    Ok(())
}
