#![allow(clippy::unwrap_used)]

use bytes::BytesMut;
use futures_util::StreamExt;
use std::{
    io::{Cursor, Write},
    time::Instant,
};
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::id::Id;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_storage::service::StorageBackend;
use trustify_test_context::TrustifyContext;
use zip::write::FileOptions;

/// Test ingesting a dataset.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
async fn ingest(ctx: TrustifyContext) -> anyhow::Result<()> {
    let service = SbomService::new(ctx.db.clone());
    let storage = &ctx.storage;

    let start = Instant::now();

    // create dataset ad-hoc

    let base = ctx.absolute_path("../datasets/ds3")?;
    let mut data = vec![];
    let mut dataset = zip::write::ZipWriter::new(Cursor::new(&mut data));
    for entry in walkdir::WalkDir::new(&base) {
        let entry = entry?;
        let Ok(path) = entry.path().strip_prefix(&base) else {
            continue;
        };

        if entry.file_type().is_file() {
            dataset.start_file_from_path(path, FileOptions::<()>::default())?;
            dataset.write_all(&(std::fs::read(entry.path())?))?;
        } else if entry.file_type().is_dir() {
            dataset.add_directory_from_path(path, FileOptions::<()>::default())?;
        }
    }
    dataset.finish()?;

    // ingest

    let result = ctx.ingestor.ingest_dataset(&data, ()).await?;

    let ingest_time = start.elapsed();

    // check ingest results

    log::info!("ingest: {}", humantime::Duration::from(ingest_time));

    assert!(result.warnings.is_empty());
    assert_eq!(result.files.len(), 64);

    // get a document

    let sbom = &result.files["spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2"];
    assert!(matches!(sbom.id, Id::Uuid(_)));

    let sbom_summary = service.fetch_sbom_summary(sbom.id.clone(), ()).await?;
    assert!(sbom_summary.is_some());
    let sbom_summary = sbom_summary.unwrap();
    assert_eq!(sbom_summary.head.name, "quarkus-bom");

    // test source document

    let source_doc = sbom_summary.source_document;

    assert!(source_doc.is_some());

    let source_doc = source_doc.unwrap();

    let storage_key = (&source_doc).try_into()?;

    let stream = storage.retrieve(storage_key).await?;
    assert!(stream.is_some());
    let mut stream = stream.unwrap();
    let mut content = BytesMut::new();
    while let Some(data) = stream.next().await {
        content.extend(&data?);
    }

    assert_eq!(content.len(), 1174356);

    // done

    Ok(())
}
