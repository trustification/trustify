//! Testing parallel upload

use csaf::Csaf;
use serde_json::Value;
use spdx_rs::models::SPDX;
use std::str::FromStr;
use std::time::Duration;
use test_context::{futures, test_context};
use test_log::test;
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_common::purl::Purl;
use trustify_module_ingestor::{
    graph::purl::creator::PurlCreator,
    graph::sbom::spdx::{parse_spdx, Information},
    service::{Discard, Format},
};
use trustify_test_context::{document_bytes, spdx::fix_spdx_rels, TrustifyContext};
use uuid::Uuid;

/// Ingest x SBOMs in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn sbom_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;

    let data = document_bytes("quarkus-bom-2.13.8.Final-redhat-00004.json").await?;
    // let data = document_bytes("openshift-container-storage-4.8.z.json.xz").await?;
    let json: Value = serde_json::from_slice(&data)?;
    let (sbom, _) = parse_spdx(&Discard, json)?;
    let sbom = fix_spdx_rels(sbom);

    // turn into 10 different SBOMs, and begin ingesting

    let mut tasks = vec![];
    for _ in 0..NUM {
        let spdx = duplicate_sbom(&sbom)?;
        let next = serde_json::to_vec(&spdx)?;

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
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn sbom_parallel_bare(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;

    // let reader = document_read("quarkus-bom-2.13.8.Final-redhat-00004.json").await?;
    let data = document_bytes("openshift-container-storage-4.8.z.json.xz").await?;
    let json: Value = serde_json::from_slice(&data)?;
    let (sbom, _) = parse_spdx(&Discard, json)?;
    let sbom = fix_spdx_rels(sbom);

    // turn into 10 different SBOMs, and begin ingesting

    let mut tasks = vec![];
    for _ in 0..NUM {
        let spdx = duplicate_sbom(&sbom)?;

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

fn duplicate_sbom(spdx: &SPDX) -> anyhow::Result<SPDX> {
    let mut spdx = spdx.clone();
    spdx.document_creation_information.spdx_document_namespace = Uuid::new_v4().to_string();

    for (n, pkg) in spdx.package_information.iter_mut().enumerate() {
        for ext in &mut pkg.external_reference {
            if n % 2 == 0 && ext.reference_type == "purl" {
                let mut purl = Purl::from_str(&ext.reference_locator)?;
                // purl.name = format!("{}{}", purl.name, Uuid::new_v4());
                purl.version = purl
                    .version
                    .map(|version| format!("{}.{}", version, Uuid::new_v4()));
            }
        }
    }

    Ok(spdx)
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

/// Ingest x CSAF documents in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn csaf_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;

    let data = document_bytes("csaf/cve-2023-33201.json").await?;
    let csaf: Csaf = serde_json::from_slice(&data)?;

    // turn into 10 different SBOMs, and begin ingesting

    let mut tasks = vec![];
    for _ in 0..NUM {
        let mut next = csaf.clone();
        next.document.tracking.id = Uuid::new_v4().to_string();
        let next = serde_json::to_vec(&next)?;

        let service = ctx.ingestor.clone();

        tasks.push(async move {
            service.ingest(&next, Format::CSAF, (), None).await?;

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

/// Ingest x CSAF documents in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn purl_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;
    const PURLS: usize = 25;

    let mut tasks = vec![];

    for _ in 0..NUM {
        let db = ctx.db.clone();
        tasks.push(async move {
            let mut creator = PurlCreator::new();

            for i in 0..PURLS {
                creator.add(Purl {
                    ty: "cargo".to_string(),
                    namespace: None,
                    name: format!("name{i}"),
                    version: None,
                    qualifiers: Default::default(),
                });
            }

            creator.create(&db).await?;

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
