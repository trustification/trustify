use super::open_sbom_xz;
use std::time::Instant;
use test_context::test_context;
use test_log::test;
use tracing::{info_span, instrument, Instrument};
use trustify_common::db::{test::TrustifyContext, Transactional};
use trustify_module_fetch::service::FetchService;
use trustify_module_ingestor::graph::{
    sbom::spdx::{parse_spdx, Information},
    Graph,
};

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
async fn ingest_spdx_medium(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let system = Graph::new(ctx.db.clone());
    let fetch = FetchService::new(ctx.db);

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

    async {
        let described = fetch
            .describes_packages(sbom.sbom.sbom_id, Default::default(), ())
            .await?;

        log::info!("{:#?}", described);
        assert_eq!(1, described.items.len());

        let packages = fetch
            .fetch_sbom_packages(
                sbom.sbom.sbom_id,
                Default::default(),
                Default::default(),
                false,
                (),
            )
            .await?;
        assert_eq!(7992, packages.total);

        Ok::<_, anyhow::Error>(())
    }
    .instrument(info_span!("assert"))
    .await?;

    let query_time = start.elapsed();

    log::info!("parse: {}", humantime::Duration::from(parse_time));
    log::info!("ingest 1: {}", humantime::Duration::from(ingest_time_1));
    log::info!("ingest 2: {}", humantime::Duration::from(ingest_time_2));
    log::info!("commit: {}", humantime::Duration::from(commit_time));
    log::info!("query: {}", humantime::Duration::from(query_time));

    Ok(())
}

// ignore because it's a slow slow slow test.
#[test_context(TrustifyContext, skip_teardown)]
#[ignore]
#[test(tokio::test)]
async fn ingest_spdx_large(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let system = Graph::new(db.clone());
    let fetch = FetchService::new(db);

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

    let described = fetch
        .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
        .await?;
    log::info!("{:#?}", described);
    assert_eq!(1, described.items.len());
    let first = &described.items[0];
    assert_eq!(3, first.cpe.len());

    let query_time = start.elapsed();

    log::info!("parse: {}", humantime::Duration::from(parse_time));
    log::info!("ingest 1: {}", humantime::Duration::from(ingest_time_1));
    log::info!("ingest 2: {}", humantime::Duration::from(ingest_time_2));
    log::info!("commit: {}", humantime::Duration::from(commit_time));
    log::info!("query: {}", humantime::Duration::from(query_time));

    Ok(())
}
