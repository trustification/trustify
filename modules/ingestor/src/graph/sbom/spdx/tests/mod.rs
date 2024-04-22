#![cfg(test)]

mod perf;

use crate::graph::sbom::spdx::Information;
use crate::graph::Graph;
use lzma::LzmaReader;
use spdx_rs::models::SPDX;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;
use test_log::test;
use tracing::{info_span, instrument};
use trustify_common::db::{Database, Transactional};
use trustify_entity::relationship::Relationship;

pub fn open_sbom(name: &str) -> anyhow::Result<impl Read> {
    let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
    let test_data = pwd.join("../../etc/test-data");

    let sbom = test_data.join(name);
    Ok(BufReader::new(File::open(sbom)?))
}

pub fn open_sbom_xz(name: &str) -> anyhow::Result<impl Read> {
    Ok(LzmaReader::new_decompressor(open_sbom(name)?)?)
}

#[instrument]
#[test(tokio::test)]
async fn parse_spdx_quarkus() -> Result<(), anyhow::Error> {
    let db = Database::for_test("parse_spdx_quarkus").await?;
    let system = Graph::new(db);

    // nope, has bad license expressions
    let sbom_data = open_sbom("quarkus-bom-2.13.8.Final-redhat-00004.json")?;

    let start = Instant::now();
    let parse_time = start.elapsed();

    let (spdx, _) = info_span!("parse json").in_scope(|| super::parse_spdx(sbom_data))?;

    let start = Instant::now();
    let tx = system.transaction().await?;

    let sbom = system
        .ingest_sbom(
            "test.com/my-sbom.json",
            "10",
            &spdx.document_creation_information.spdx_document_namespace,
            Information(&spdx),
            &tx,
        )
        .await?;

    sbom.ingest_spdx(spdx, &tx).await?;
    let ingest_time = start.elapsed();
    let start = Instant::now();

    // commit, then test
    tx.commit().await?;

    let described_cpe222 = sbom.describes_cpe22s(Transactional::None).await?;
    log::info!("{:#?}", described_cpe222);
    assert_eq!(1, described_cpe222.len());

    let described_packages = sbom.describes_packages(Transactional::None).await?;
    log::info!("{:#?}", described_packages);

    let contains = sbom
        .related_packages(
            Relationship::ContainedBy,
            described_packages[0].clone().into(),
            Transactional::None,
        )
        .await?;

    log::info!("{}", contains.len());

    assert!(contains.len() > 500);

    let query_time = start.elapsed();

    log::info!("parse {}ms", parse_time.as_millis());
    log::info!("ingest {}ms", ingest_time.as_millis());
    log::info!("query {}ms", query_time.as_millis());

    Ok(())
}

#[test(tokio::test)]
async fn parse_spdx() -> Result<(), anyhow::Error> {
    let db = Database::for_test("parse_spdx").await?;
    let system = Graph::new(db);

    let sbom = open_sbom("ubi9-9.2-755.1697625012.json")?;

    let tx = system.transaction().await?;

    let start = Instant::now();
    let (spdx, _) = super::parse_spdx(sbom)?;
    let parse_time = start.elapsed();

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

    sbom.ingest_spdx(spdx, &tx).await?;

    tx.commit().await?;

    let ingest_time = start.elapsed();
    let start = Instant::now();

    let described = sbom.describes_packages(Transactional::None).await?;

    assert_eq!(1, described.len());

    let contains = sbom
        .related_packages(
            Relationship::ContainedBy,
            described[0].clone().into(),
            Transactional::None,
        )
        .await?;

    log::info!("{}", contains.len());

    assert!(contains.len() > 500);

    let query_time = start.elapsed();

    log::info!("parse {}ms", parse_time.as_millis());
    log::info!("ingest {}ms", ingest_time.as_millis());
    log::info!("query {}ms", query_time.as_millis());

    Ok(())
}
