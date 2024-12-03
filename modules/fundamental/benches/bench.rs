use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

#[allow(clippy::expect_used, clippy::unwrap_used)]
pub(crate) mod trustify_benches {
    use std::io::Error;
    use std::ops::Add;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use cpe::cpe::Cpe;
    use cpe::uri::OwnedUri;
    use criterion::{black_box, Criterion};
    use csaf::definitions::{BranchesT, ProductIdentificationHelper};
    use csaf::product_tree::ProductTree;
    use csaf::vulnerability::Vulnerability;
    use csaf::Csaf;
    use packageurl::PackageUrl;
    use sea_orm::ConnectionTrait;
    use test_context::AsyncTestContext;
    use tokio::runtime::Runtime;
    use trustify_entity::labels::Labels;
    use trustify_module_ingestor::service::Format;
    use trustify_test_context::{document, TrustifyContext};

    pub fn ingestion(c: &mut Criterion) {
        let (runtime, ctx) = setup_runtime_and_ctx();
        c.bench_function("ingestion_csaf", |b| {
            b.to_async(&runtime).iter_custom(|count| {
                let ctx = ctx.clone();
                async move {
                    log::info!("db reset...");
                    reset_db(&ctx).await;

                    let mut duration = Duration::default();
                    for i in 0..count {
                        log::info!("inserting document {}...", i);
                        let data = document_generated_from("csaf/cve-2023-33201.json", i)
                            .await
                            .expect("data ok");

                        let start = Instant::now();
                        black_box(
                            ctx.ingestor
                                .ingest(&data, Format::Advisory, Labels::default(), None)
                                .await
                                .expect("ingest ok"),
                        );
                        duration = duration.add(start.elapsed());
                    }

                    duration
                }
            });
        });
    }

    async fn document_generated_from(path: &str, rev: u64) -> Result<Bytes, Error> {
        let (mut doc, _): (Csaf, _) = document(path).await.expect("load ok");
        doc.document.tracking.id = format!("{}-{}", doc.document.tracking.id, rev);

        fn rev_branches(branches: &mut Option<BranchesT>, rev: u64) {
            if let Some(BranchesT(branches)) = branches {
                for branch in branches.iter_mut() {
                    if let Some(product) = &mut branch.product {
                        rev_product_helper(&mut product.product_identification_helper, rev);
                    }
                    rev_branches(&mut branch.branches, rev);
                }
            }
        }

        fn rev_product_helper(helper: &mut Option<ProductIdentificationHelper>, rev: u64) {
            if let Some(helper) = helper {
                if let Some(cpe) = &mut helper.cpe {
                    helper.cpe = Some(rev_cpe(cpe, rev))
                }
                if let Some(purl) = &mut helper.purl {
                    helper.purl = Some(rev_purl(purl.clone(), rev));
                }
            }
        }

        fn rev_purl(from: PackageUrl, rev: u64) -> PackageUrl {
            let name = from.name();
            let new_name = format!("{}-{}", name, rev);
            PackageUrl::from_str(
                from.to_string()
                    .replacen(name, new_name.as_str(), 1)
                    .as_str(),
            )
            .unwrap()
        }
        fn rev_cpe(cpe: &OwnedUri, rev: u64) -> OwnedUri {
            let uri = format!("{:0}", cpe);
            let mut uri = cpe::uri::Uri::parse(uri.as_str()).unwrap();
            let x = format!("{}_{}", uri.product(), rev);
            uri.set_product(x.as_str()).unwrap();
            uri.to_owned()
        }
        fn rev_product_tree(product_tree: &mut ProductTree, rev: u64) {
            rev_branches(&mut product_tree.branches, rev);
            for relationships in product_tree.relationships.iter_mut() {
                for relationship in relationships.iter_mut() {
                    // rev_product_id(&mut relationship.full_product_name.product_id, rev);
                    rev_product_helper(
                        &mut relationship.full_product_name.product_identification_helper,
                        rev,
                    );
                }
            }
        }
        fn rev_vulnerability(vulnerability: &mut Vulnerability, rev: u64) {
            for cve in vulnerability.cve.iter_mut() {
                *cve = format!("{}-{}", cve, rev);
            }
        }

        for product_tree in doc.product_tree.iter_mut() {
            rev_product_tree(product_tree, rev);
        }
        for vulnerabilities in doc.vulnerabilities.iter_mut() {
            for vulnerability in vulnerabilities.iter_mut() {
                rev_vulnerability(vulnerability, rev);
            }
        }

        let data = serde_json::to_vec_pretty(&doc).expect("serialize ok");
        Ok(Bytes::from(data))
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
