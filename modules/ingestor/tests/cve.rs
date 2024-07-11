#![allow(clippy::expect_used)]

use anyhow::bail;
use futures_util::stream;
use std::convert::Infallible;
use test_context::test_context;
use test_log::test;
use trustify_common::id::Id;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest_cve(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let ingestor = IngestorService::new(ctx.graph.clone(), ctx.storage.clone());

    let data = ctx.document_bytes("cve/CVE-2021-32714.json").await?;

    // ingest once

    let result = ingestor
        .ingest(
            (),
            None,
            Format::CVE,
            stream::iter([Ok::<_, Infallible>(data.clone())]),
        )
        .await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let adv = ctx
        .graph
        .get_advisory_by_id(id, ())
        .await?
        .expect("must be found");
    let vuln = ctx
        .graph
        .get_vulnerability("CVE-2021-32714", ())
        .await?
        .expect("Must be found");

    let descriptions = vuln.descriptions("en", ()).await?;

    assert_eq!(descriptions.len(), 1);
    assert_eq!(adv.vulnerabilities(()).await?.len(), 1);

    // ingest second time

    ingestor
        .ingest(
            (),
            None,
            Format::CVE,
            stream::iter([Ok::<_, Infallible>(data)]),
        )
        .await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let adv = ctx
        .graph
        .get_advisory_by_id(id, ())
        .await?
        .expect("must be found");
    let vuln = ctx
        .graph
        .get_vulnerability("CVE-2021-32714", ())
        .await?
        .expect("Must be found");

    let descriptions = vuln.descriptions("en", ()).await?;

    // must still be one

    assert_eq!(descriptions.len(), 1);
    assert_eq!(adv.vulnerabilities(()).await?.len(), 1);

    // done

    Ok(())
}
