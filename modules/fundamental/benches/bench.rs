use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

#[allow(clippy::expect_used, clippy::unwrap_used)]
pub(crate) mod trustify_benches {
    use std::future::Future;
    use std::io;
    use std::io::Error;
    use std::ops::Add;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use criterion::{black_box, Criterion};
    use csaf::Csaf;
    use futures_util::stream;
    use futures_util::stream::Once;
    use sea_orm::ConnectionTrait;
    use test_context::AsyncTestContext;
    use tokio::runtime::Runtime;

    use trustify_common::db::Transactional;
    use trustify_entity::labels::Labels;
    use trustify_module_ingestor::service::Format;
    use trustify_test_context::{document_bytes, TrustifyContext};

    pub fn ingestion(c: &mut Criterion) {
        let (runtime, ctx) = setup_runtime_and_ctx();
        c.bench_function("ingestion_csaf", |b| {
            b.to_async(&runtime).iter_custom(|count| {
                let ctx = ctx.clone();
                async move {
                    reset_db(&ctx).await;

                    let mut duration = Duration::default();
                    for i in 0..count {
                        let stream =
                            document_stream_generated_from("csaf/cve-2023-33201.json", i).await;

                        let start = Instant::now();
                        black_box(
                            ctx.ingestor
                                .ingest::<_, io::Error>(
                                    Labels::default(),
                                    None,
                                    Format::CSAF,
                                    stream,
                                )
                                .await
                                .expect("ingest ok"),
                        );
                        duration = duration.add(start.elapsed())
                    }

                    duration
                }
            });
        });
    }

    async fn document_stream_generated_from(
        path: &str,
        rev: u64,
    ) -> Once<impl Future<Output = Result<Bytes, Error>> + Sized> {
        let payload = document_bytes(path).await.expect("load ok");
        let mut doc: Csaf = serde_json::from_slice(payload.as_ref()).expect("parse ok");
        doc.document.tracking.id = format!("{}-{}", doc.document.tracking.id, rev);
        let data = serde_json::to_vec_pretty(&doc).expect("serialize ok");
        stream::once(async { Ok(Bytes::from(data)) })
    }

    fn setup_runtime_and_ctx() -> (Runtime, Arc<TrustifyContext>) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let ctx = runtime.block_on(async { TrustifyContext::setup().await });
        (runtime, Arc::new(ctx))
    }

    async fn reset_db(ctx: &Arc<TrustifyContext>) {
        // reset DB tables to a clean state...
        for table in [
            "advisory",
            "base_purl",
            "versioned_purl",
            "qualified_purl",
            "cvss3",
            "cpe",
            "version_range",
            "vulnerability",
        ] {
            ctx.db
                .clone()
                .connection(&Transactional::None)
                .execute_unprepared(format!("DELETE FROM {table} WHERE 1=1").as_str())
                .await
                .expect("DELETE ok");
        }
        ctx.db
            .clone()
            .connection(&Transactional::None)
            .execute_unprepared("VACUUM ANALYZE")
            .await
            .expect("vacuum analyze ok");
    }
}

criterion_group! {
  name = benches;
  config = Criterion::default().measurement_time(Duration::from_secs(15));
  targets = trustify_benches::ingestion
}
criterion_main!(benches);
