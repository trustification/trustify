#![cfg(test)]

mod basic;
mod perf;

use lzma::LzmaReader;
use spdx_rs::models::SPDX;
use std::collections::HashSet;
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;
use tracing::{info_span, instrument, Instrument};
use trustify_common::db::test::TrustifyContext;
use trustify_common::db::Database;
use trustify_module_fetch::service::FetchService;
use trustify_module_ingestor::graph::{
    sbom::{
        spdx::{parse_spdx, Information},
        SbomContext,
    },
    Graph,
};

#[instrument]
pub fn open_sbom(name: &str) -> anyhow::Result<impl Read> {
    let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
    let test_data = pwd.join("../etc/test-data");

    let sbom = test_data.join(name);
    Ok(BufReader::new(File::open(sbom)?))
}

#[instrument]
pub fn open_sbom_xz(name: &str) -> anyhow::Result<impl Read> {
    Ok(LzmaReader::new_decompressor(open_sbom(name)?)?)
}

/// remove all relationships having broken references
pub fn fix_rels(mut spdx: SPDX) -> SPDX {
    let mut ids = spdx
        .package_information
        .iter()
        .map(|p| &p.package_spdx_identifier)
        .collect::<HashSet<_>>();

    ids.insert(&spdx.document_creation_information.spdx_identifier);

    spdx.relationships.retain(|rel| {
        let r = ids.contains(&rel.spdx_element_id) && ids.contains(&rel.related_spdx_element);
        if !r {
            log::warn!(
                "Dropping - left: {}, rel: {:?}, right: {}",
                rel.spdx_element_id,
                rel.relationship_type,
                rel.related_spdx_element
            );
        }
        r
    });

    spdx
}

pub struct WithContext {
    pub sbom: SbomContext,
    pub db: Database,
    pub graph: Graph,
    pub fetch: FetchService,
}

#[instrument(skip(ctx, f))]
async fn test_with<F, Fut>(ctx: TrustifyContext, sbom: &str, f: F) -> anyhow::Result<()>
where
    F: FnOnce(WithContext) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    // The `ctx` must live until the end of this function. Otherwise, it will tear down the database
    // while we're testing. So we take the `db` and offer it to the test, but we hold on the `ctx`
    // instance until that test returns.

    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let fetch = FetchService::new(db.clone());

    let start = Instant::now();
    let (spdx, _) = info_span!("parse json").in_scope(|| {
        Ok::<_, anyhow::Error>(if sbom.ends_with(".xz") {
            parse_spdx(open_sbom_xz(sbom)?)?
        } else {
            parse_spdx(open_sbom(sbom)?)?
        })
    })?;

    let spdx = fix_rels(spdx);
    let parse_time = start.elapsed();

    let tx = graph.transaction().await?;

    let start = Instant::now();
    let sbom = graph
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
    sbom.ingest_spdx(spdx.clone(), &tx).await?;
    let ingest_time_2 = start.elapsed();

    // commit

    let start = Instant::now();
    tx.commit().await?;
    let commit_time = start.elapsed();

    // now test

    let start = Instant::now();
    f(WithContext {
        sbom,
        db,
        graph,
        fetch,
    })
    .instrument(info_span!("assert"))
    .await?;
    let test_time = start.elapsed();

    // log durations

    log::info!("parse: {}", humantime::Duration::from(parse_time));
    log::info!("ingest 1: {}", humantime::Duration::from(ingest_time_1));
    log::info!("ingest 2: {}", humantime::Duration::from(ingest_time_2));
    log::info!("commit: {}", humantime::Duration::from(commit_time));
    log::info!("test: {}", humantime::Duration::from(test_time));

    Ok(())
}
