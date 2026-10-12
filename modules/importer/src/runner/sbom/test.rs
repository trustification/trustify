use super::{report::SbomReportVisitor, storage::StorageVisitor};
use crate::runner::{
    common::storage::StorageError,
    report::{Phase, ReportBuilder, ReportVisitor, Severity},
    test::{
        TestRunContext, assert_message, assert_not_persisted, assert_send, assert_send_sync,
        persisted_document,
    },
};
use bytes::Bytes;
use parking_lot::Mutex;
use sbom_walker::{
    discover::{DiscoveredContext, DiscoveredSbom},
    model::metadata::SourceMetadata,
    retrieve::{RetrievalContext, RetrievedSbom},
    source::HttpSource,
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::{
    sync::{Arc, atomic::Ordering},
    time::SystemTime,
};
use test_context::test_context;
use test_log::test;
use tokio::task::LocalSet;
use trustify_common::db::ReadWrite;
use trustify_entity::{labels::Labels, sbom};
use trustify_test_context::{TrustifyContext, document_bytes};
use url::Url;
use uuid::Uuid;
use walker_common::validate::ValidationError;

const SOURCE: &str = "https://example.test/sbom/";
const FILE: &str = "https://example.test/sbom/test.json";

fn visitor(ctx: &TrustifyContext, context: TestRunContext) -> SbomReportVisitor<TestRunContext> {
    let report = Arc::new(Mutex::new(ReportBuilder::new()));
    SbomReportVisitor {
        next: ReportVisitor::new(
            report.clone(),
            StorageVisitor {
                context,
                source: SOURCE.into(),
                max_size: None,
                labels: Labels::from_one("test", "send-callback"),
                ingestor: ctx.ingestor.clone(),
                db: ReadWrite::new(ctx.db.clone()),
                report,
            },
        ),
        ignore_errors: Default::default(),
    }
}

async fn document(tag: &str) -> anyhow::Result<ValidatedSbom> {
    let data = document_bytes("spdx/described-by-supplier.json").await?;
    let mut value: serde_json::Value = serde_json::from_slice(&data)?;
    let tag = format!("{tag}-{}", Uuid::new_v4());
    value["documentNamespace"] = format!("https://example.test/{tag}").into();
    value["name"] = tag.into();
    Ok(ValidatedSbom {
        retrieved: RetrievedSbom {
            discovered: DiscoveredSbom {
                url: Url::parse(FILE)?,
                modified: SystemTime::UNIX_EPOCH,
            },
            data: Bytes::from(serde_json::to_vec(&value)?),
            signature: None,
            sha256: None,
            sha512: None,
            metadata: Default::default(),
        },
    })
}

async fn assert_persisted(ctx: &TrustifyContext, data: &[u8]) -> anyhow::Result<()> {
    let id = persisted_document(ctx, data).await?;
    let model = sbom::Entity::find()
        .filter(sbom::Column::SourceDocumentId.eq(id))
        .one(&ctx.db)
        .await?
        .expect("callback must persist the SBOM");
    assert_eq!(
        model.labels,
        Labels::new()
            .add("source", SOURCE)
            .add("importer", "callback-test")
            .add("file", FILE)
            .add("test", "send-callback")
            .add("type", "spdx")
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn storage_and_report_callbacks_are_send_and_persist(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    LocalSet::new()
        .run_until(async {
            assert_send_sync::<StorageVisitor<TestRunContext>>();
            assert_send_sync::<ReportVisitor<StorageVisitor<TestRunContext>>>();
            assert_send_sync::<SbomReportVisitor<TestRunContext>>();
            let context = TestRunContext::default();
            let visitor = visitor(ctx, context.clone());
            let metadata = SourceMetadata { keys: vec![] };
            let discovered = DiscoveredContext {
                metadata: &metadata,
            };
            let keys = vec![];
            let retrieval = RetrievalContext {
                discovered: &discovered,
                keys: &keys,
            };
            let validation = ValidationContext {
                retrieval: &retrieval,
            };
            assert_send(visitor.next.next.visit_context(&validation)).await?;
            assert_send(visitor.visit_context(&validation)).await?;

            let doc = document("storage-success").await?;
            let data = doc.data.clone();
            assert_send(visitor.next.next.visit_sbom(&(), Ok(doc))).await?;
            assert_persisted(ctx, &data).await?;
            assert_eq!(
                visitor.next.report.lock().clone().build().number_of_items,
                0
            );

            let doc = document("report-success").await?;
            let data = doc.data.clone();
            assert_send(visitor.visit_sbom(&(), Ok(doc))).await?;
            assert_persisted(ctx, &data).await?;
            let report = visitor.next.report.lock().clone().build();
            assert_eq!(report.number_of_items, 1);
            assert!(
                !report
                    .messages
                    .values()
                    .flat_map(|files| files.values())
                    .flatten()
                    .any(|message| message.severity == Severity::Error)
            );
            assert_eq!(context.checks.load(Ordering::SeqCst), 2);
            Ok(())
        })
        .await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn cancellation_propagates_after_storage_and_report_persist(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    LocalSet::new()
        .run_until(async {
            for through_report in [false, true] {
                let context = TestRunContext::default();
                context.canceled.store(true, Ordering::SeqCst);
                let visitor = visitor(ctx, context.clone());
                let doc = document(if through_report {
                    "report-canceled"
                } else {
                    "storage-canceled"
                })
                .await?;
                let data = doc.data.clone();
                let result = if through_report {
                    assert_send(visitor.visit_sbom(&(), Ok(doc))).await
                } else {
                    assert_send(visitor.next.next.visit_sbom(&(), Ok(doc))).await
                };
                assert!(matches!(result, Err(StorageError::Canceled)));
                assert_persisted(ctx, &data).await?;
                assert_eq!(context.checks.load(Ordering::SeqCst), 1);
                let report = visitor.next.report.lock().clone().build();
                assert_eq!(report.number_of_items, usize::from(through_report));
                assert!(
                    report
                        .messages
                        .values()
                        .flat_map(|files| files.values())
                        .flatten()
                        .all(|message| message.severity != Severity::Error)
                );
            }
            Ok(())
        })
        .await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn report_counts_ignored_validation_upload_and_size_errors(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    LocalSet::new()
        .run_until(async {
            let context = TestRunContext::default();
            let mut visitor = visitor(ctx, context.clone());
            let doc = document("errors").await?;
            let data = doc.data.clone();
            let digest_error = || ValidationError::<HttpSource>::DigestMismatch {
                expected: "expected".into(),
                actual: "actual".into(),
                retrieved: doc.retrieved.clone(),
            };
            assert!(matches!(
                assert_send(visitor.next.next.visit_sbom(&(), Err(digest_error()))).await,
                Err(StorageError::Validation(_))
            ));
            assert_send(visitor.visit_sbom(&(), Err(digest_error()))).await?;
            let report = visitor.next.report.lock().clone().build();
            assert_eq!(report.number_of_items, 1);
            assert_message(
                &report,
                Phase::Validation,
                FILE,
                Severity::Error,
                "digest mismatch",
            );

            let mut invalid = doc.clone();
            invalid.retrieved.discovered.url =
                Url::parse("https://example.test/sbom/invalid.json")?;
            invalid.retrieved.data = Bytes::from(format!("not a document {}", Uuid::new_v4()));
            let invalid_data = invalid.data.clone();
            assert!(matches!(
                assert_send(visitor.next.next.visit_sbom(&(), Ok(invalid.clone()))).await,
                Err(StorageError::Storage(_))
            ));
            assert_send(visitor.visit_sbom(&(), Ok(invalid))).await?;
            let report = visitor.next.report.lock().clone().build();
            assert_eq!(report.number_of_items, 2);
            assert_message(
                &report,
                Phase::Upload,
                "https://example.test/sbom/invalid.json",
                Severity::Error,
                "upload failed",
            );

            visitor.next.next.max_size = Some(1);
            assert_send(visitor.visit_sbom(&(), Ok(doc))).await?;
            let report = visitor.next.report.lock().clone().build();
            assert_eq!(report.number_of_items, 3);
            assert_message(
                &report,
                Phase::Upload,
                FILE,
                Severity::Warning,
                "size restriction",
            );
            assert_eq!(context.checks.load(Ordering::SeqCst), 0);
            assert_not_persisted(ctx, &data).await?;
            assert_not_persisted(ctx, &invalid_data).await?;
            Ok(())
        })
        .await
}
