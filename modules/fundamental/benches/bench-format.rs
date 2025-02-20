use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

#[allow(clippy::expect_used, clippy::unwrap_used)]
pub(crate) mod trustify_benches {
    use std::ops::Add;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use criterion::{black_box, Criterion};
    use sea_orm::ConnectionTrait;
    use test_context::AsyncTestContext;
    use tokio::runtime::Runtime;
    use trustify_test_context::TrustifyContext;

    pub fn ingestion(c: &mut Criterion) {
        let (runtime, ctx) = setup_runtime_and_ctx();
        c.bench_function("ingest_documents", |b| {
            b.to_async(&runtime).iter_custom(|count| {
                let ctx = ctx.clone();
                async move {
                    log::info!("db reset...");
                    reset_db(&ctx).await;

                    let mut duration = Duration::default();
                    for i in 0..count {
                        log::info!("inserting document {}...", i);
                        let start = Instant::now();
                        black_box(
                            &ctx.ingest_documents([
                                "csaf/rhsa-2024-2705.json",
                                // "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
                                // "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
                            ])
                            .await
                            .expect("ok"),
                        );
                        duration = duration.add(start.elapsed());
                    }

                    duration
                }
            });
        });
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
            "purl_license_assertion",
        ] {
            ctx.db
                .execute_unprepared(format!("DELETE FROM {table} WHERE 1=1").as_str())
                .await
                .expect("DELETE ok");
        }
        ctx.db
            .execute_unprepared("VACUUM ANALYZE")
            .await
            .expect("vacuum analyze ok");
    }
}

criterion_group! {
  name = benches;
  // since insertion takes so long, we need to reduce the sample
  // size and increase the time so that we can get a few iterations
  // in between db resets.
  config = Criterion::default()
    .measurement_time(Duration::from_secs(15))
    .sample_size(10);
  targets = trustify_benches::ingestion
}
criterion_main!(benches);
