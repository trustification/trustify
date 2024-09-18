//! Testing parallel upload

use serde_json::Value;
use std::time::Duration;
use test_context::{futures, test_context};
use test_log::test;
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_ingestor::{
    graph::sbom::spdx::{parse_spdx, Information},
    service::{Discard, Format},
};
use trustify_test_context::{document_read, spdx::fix_spdx_rels, TrustifyContext};
use uuid::Uuid;

/// Ingest x SBOMs in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn quarkus_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 50;

    let reader = document_read("quarkus-bom-2.13.8.Final-redhat-00004.json").await?;
    let json: Value = serde_json::from_reader(reader)?;
    let (sbom, _) = parse_spdx(&Discard, json)?;
    let sbom = fix_spdx_rels(sbom);

    // turn into 10 different SBOMs, and begin ingesting

    let mut tasks = vec![];
    for _ in 0..NUM {
        let mut next = sbom.clone();
        next.document_creation_information.spdx_document_namespace = Uuid::new_v4().to_string();
        let next = serde_json::to_vec(&next)?;

        let service = ctx.ingestor.clone();

        tasks.push(async move {
            service.ingest(&next, Format::SPDX, (), None).await?;

            Ok::<_, anyhow::Error>(())
        });
    }

    // progress ingestion tasks

    let result = futures::future::join_all(tasks).await;

    // now test

    assert_all_ok::<NUM>(result);

    // done

    Ok(())
}

/// Ingest x SBOMs in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn quarkus_parallel_2(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 50;

    let reader = document_read("quarkus-bom-2.13.8.Final-redhat-00004.json").await?;
    let json: Value = serde_json::from_reader(reader)?;
    let (sbom, _) = parse_spdx(&Discard, json)?;
    let sbom = fix_spdx_rels(sbom);

    // turn into 10 different SBOMs, and begin ingesting

    let mut tasks = vec![];
    for _ in 0..NUM {
        let mut spdx = sbom.clone();
        spdx.document_creation_information.spdx_document_namespace = Uuid::new_v4().to_string();

        let db = ctx.db.clone();
        let graph = ctx.graph.clone();

        let data = serde_json::to_vec(&spdx)?;
        let digests = Digests::digest(&data);

        tasks.push(async move {
            let tx = graph.transaction().await?;

            let document_id = spdx
                .document_creation_information
                .spdx_document_namespace
                .clone();

            let sbom = graph
                .ingest_sbom((), &digests, &document_id, Information(&spdx), &tx)
                .await?;

            tokio::time::sleep(Duration::from_secs(5)).await;

            sbom.ingest_spdx(spdx, &Discard, &tx).await?;

            tokio::time::sleep(Duration::from_secs(5)).await;

            tx.commit().await?;

            tokio::time::sleep(Duration::from_secs(5)).await;

            let id = sbom.sbom.sbom_id.to_string();
            let analysis_service = AnalysisService::new(db);

            analysis_service.load_graphs(vec![id], ()).await?;

            tokio::time::sleep(Duration::from_secs(5)).await;

            Ok::<_, anyhow::Error>(())
        });
    }

    // progress ingestion tasks

    let result = futures::future::join_all(tasks).await;

    // now test

    assert_all_ok::<NUM>(result);

    // done

    Ok(())
}

fn assert_all_ok<const NUM: usize>(result: Vec<Result<(), anyhow::Error>>) {
    assert_eq!(result.len(), NUM);

    let ok = result
        .iter()
        .filter(|r| match r {
            Ok(_) => true,
            Err(err) => {
                log::warn!("failed: {err}");
                false
            }
        })
        .count();
    assert_eq!(ok, NUM);
}
