use criterion::{criterion_group, criterion_main};

#[allow(clippy::expect_used, clippy::unwrap_used)]
pub(crate) mod trustify_benches {
    use criterion::Criterion;
    use std::io;
    use test_context::AsyncTestContext;
    use tokio::runtime::Runtime;

    use trustify_entity::labels::Labels;
    use trustify_module_ingestor::service::Format;
    use trustify_test_context::{document_stream, TrustifyContext};

    fn setup_runtime_and_ctx() -> (Runtime, TrustifyContext) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let ctx = runtime.block_on(async { TrustifyContext::setup().await });
        (runtime, ctx)
    }

    pub fn ingestion(c: &mut Criterion) {
        let (runtime, ctx) = setup_runtime_and_ctx();
        c.bench_function("ingestion_csaf", |b| {
            b.to_async(&runtime).iter(|| async {
                // todo: how do we reset the deb so we can re-import the doc?
                let payload = document_stream("csaf/cve-2023-33201.json")
                    .await
                    .expect("load ok");
                ctx.ingestor
                    .ingest::<_, io::Error>(Labels::default(), None, Format::CSAF, payload)
                    .await
                    .expect("ingest ok");
            });
        });
    }
}
criterion_group!(benches, trustify_benches::ingestion);
criterion_main!(benches);
