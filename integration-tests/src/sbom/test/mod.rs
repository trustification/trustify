#![cfg(test)]

mod cyclonedx;
mod perf;
mod spdx;

use cyclonedx_bom::prelude::Bom;
use lzma::LzmaReader;
use spdx_rs::models::SPDX;
use std::collections::HashSet;
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Instant;
use tracing::{info_span, instrument, Instrument};
use trustify_common::db::{Database, Transactional};
use trustify_common::hashing::Digests;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_ingestor::graph::{
    sbom::{self, spdx::parse_spdx, SbomContext, SbomInformation},
    Graph,
};
use trustify_module_ingestor::service::Discard;
use trustify_test_context::TrustifyContext;

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
pub fn fix_spdx_rels(mut spdx: SPDX) -> SPDX {
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
    pub service: SbomService,
}

#[instrument(skip(ctx, f))]
async fn test_with_spdx<F, Fut>(ctx: TrustifyContext, sbom: &str, f: F) -> anyhow::Result<()>
where
    F: FnOnce(WithContext) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    test_with(
        ctx,
        sbom,
        |data| {
            let (sbom, _) = parse_spdx(&Discard, &*data)?;
            Ok(fix_spdx_rels(sbom))
        },
        |ctx, sbom, tx| {
            Box::pin(async move {
                ctx.ingest_spdx(sbom.clone(), &Discard, &tx).await?;
                Ok(())
            })
        },
        |sbom| sbom::spdx::Information(sbom).into(),
        f,
    )
    .await
}

#[instrument(skip(ctx, f))]
async fn test_with_cyclonedx<F, Fut>(ctx: TrustifyContext, sbom: &str, f: F) -> anyhow::Result<()>
where
    F: FnOnce(WithContext) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    test_with(
        ctx,
        sbom,
        |data| Ok(Bom::parse_from_json(&*data)?),
        |ctx, sbom, tx| Box::pin(async move { ctx.ingest_cyclonedx(sbom.clone(), &tx).await }),
        |sbom| sbom::cyclonedx::Information(sbom).into(),
        f,
    )
    .await
}

#[instrument(skip(ctx, p, i, c, f))]
async fn test_with<B, P, I, C, F, FFut>(
    ctx: TrustifyContext,
    sbom: &str,
    p: P,
    i: I,
    c: C,
    f: F,
) -> anyhow::Result<()>
where
    P: FnOnce(Vec<u8>) -> anyhow::Result<B>,
    for<'a> I: FnOnce(
        &'a SbomContext,
        B,
        &'a Transactional,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>>,
    C: FnOnce(&B) -> SbomInformation,
    F: FnOnce(WithContext) -> FFut,
    FFut: Future<Output = anyhow::Result<()>>,
{
    // The `ctx` must live until the end of this function. Otherwise, it will tear down the database
    // while we're testing. So we take the `db` and offer it to the test, but we hold on the `ctx`
    // instance until that test returns.

    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let service = SbomService::new(db.clone());

    let start = Instant::now();
    let sbom = info_span!("parse json").in_scope(|| {
        let mut buffer = Vec::new();
        if sbom.ends_with(".xz") {
            open_sbom_xz(sbom)?.read_to_end(&mut buffer)?;
        } else {
            open_sbom(sbom)?.read_to_end(&mut buffer)?;
        };

        p(buffer)
    })?;

    let parse_time = start.elapsed();

    let tx = graph.transaction().await?;

    let start = Instant::now();
    let ctx = graph
        .ingest_sbom(
            ("source", "test.com/my-sbom.json"),
            &Digests::digest("10"),
            "document-id",
            c(&sbom),
            &tx,
        )
        .await?;
    let ingest_time_1 = start.elapsed();

    let start = Instant::now();
    i(&ctx, sbom, &tx).await?;
    let ingest_time_2 = start.elapsed();

    // commit

    let start = Instant::now();
    tx.commit().await?;
    let commit_time = start.elapsed();

    // now test

    let start = Instant::now();
    f(WithContext {
        sbom: ctx,
        db,
        graph,
        service,
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
