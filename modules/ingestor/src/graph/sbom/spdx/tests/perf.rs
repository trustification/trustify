use super::{open_sbom, open_sbom_xz};
use crate::graph::sbom::spdx::{parse_spdx, Information};
use crate::graph::Graph;
use lzma::LzmaReader;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;
use test_log::test;
use tracing::{info_span, instrument};
use trustify_common::db::{Database, Transactional};
use trustify_entity::relationship::Relationship;

// #[ignore] no need to ignore, this runs about a minute and a half, and we should improve on that
#[test(tokio::test)]
#[instrument]
async fn ingest_spdx_medium() -> Result<(), anyhow::Error> {
    let db = Database::for_test("ingest_spdx_medium").await?;
    let system = Graph::new(db);

    let sbom = open_sbom_xz("openshift-container-storage-4.8.z.json.xz")?;

    // parse file

    let start = Instant::now();
    let (spdx, _) = info_span!("parse json").in_scope(|| parse_spdx(sbom))?;
    let parse_time = start.elapsed();

    // start transaction

    let tx = system.transaction().await?;

    // start ingestion process

    let start = Instant::now();
    let sbom = system
        .ingest_sbom(
            "test.com/my-sbom.json",
            "10",
            &spdx.document_creation_information.spdx_document_namespace,
            Information(&spdx),
            &tx,
        )
        .await?;

    let ingest_time_1 = start.elapsed();

    let start = Instant::now();
    sbom.ingest_spdx(spdx, &tx).await?;
    let ingest_time_2 = start.elapsed();

    let start = Instant::now();
    tx.commit().await?;
    let commit_time = start.elapsed();

    // query

    let start = Instant::now();

    let described_cpe222 = sbom.describes_cpe22s(Transactional::None).await?;
    assert_eq!(1, described_cpe222.len());

    let described_packages = sbom.describes_packages(Transactional::None).await?;
    log::info!("{:#?}", described_packages);

    let query_time = start.elapsed();

    log::info!("parse: {}", humantime::Duration::from(parse_time));
    log::info!("ingest 1: {}", humantime::Duration::from(ingest_time_1));
    log::info!("ingest 2: {}", humantime::Duration::from(ingest_time_2));
    log::info!("commit: {}", humantime::Duration::from(commit_time));
    log::info!("query: {}", humantime::Duration::from(query_time));

    Ok(())
}

// ignore because it's a slow slow slow test.
#[ignore]
#[test(tokio::test)]
async fn ingest_spdx_large() -> Result<(), anyhow::Error> {
    let db = Database::for_test("ingest_spdx_large").await?;
    let system = Graph::new(db);

    let sbom = open_sbom_xz("openshift-4.13.json.xz")?;

    let tx = system.transaction().await?;

    let start = Instant::now();
    let (spdx, _) = parse_spdx(sbom)?;
    let parse_time = start.elapsed();

    let start = Instant::now();
    let sbom = system
        .ingest_sbom(
            "test.com/my-sbom.json",
            "10",
            &spdx.document_creation_information.spdx_document_namespace,
            Information(&spdx),
            Transactional::None,
        )
        .await?;
    let ingest_time_1 = start.elapsed();

    let start = Instant::now();
    sbom.ingest_spdx(spdx, &tx).await?;
    let ingest_time_2 = start.elapsed();

    let start = Instant::now();
    tx.commit().await?;
    let commit_time = start.elapsed();

    let start = Instant::now();

    let described_cpe222 = sbom.describes_cpe22s(Transactional::None).await?;
    log::info!("{:#?}", described_cpe222);
    assert_eq!(3, described_cpe222.len());

    let described_packages = sbom.describes_packages(Transactional::None).await?;
    log::info!("{:#?}", described_packages);

    let query_time = start.elapsed();

    log::info!("parse: {}", humantime::Duration::from(parse_time));
    log::info!("ingest 1: {}", humantime::Duration::from(ingest_time_1));
    log::info!("ingest 2: {}", humantime::Duration::from(ingest_time_2));
    log::info!("commit: {}", humantime::Duration::from(commit_time));
    log::info!("query: {}", humantime::Duration::from(query_time));

    Ok(())
}
