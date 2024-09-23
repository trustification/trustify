use csaf::{definitions::ProductIdT, document::Revision, Csaf};
use test_context::test_context;
use test_log::test;
use trustify_common::purl::Purl;
use trustify_module_fundamental::{
    purl::{
        model::details::purl::{PurlStatus, StatusContext},
        service::PurlService,
    },
    vulnerability::{model::VulnerabilityHead, service::VulnerabilityService},
};
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::{document_bytes, TrustifyContext};

/// Ensure that ingesting the same document twice, leads to the same ID.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn equal(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = twice(&ctx, |csaf| csaf, |csaf| csaf).await?;

    // no change, same result

    assert_eq!(r1.id, r2.id);

    // check info

    let vuln = VulnerabilityService::new(ctx.db.clone());
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", ())
        .await?
        .expect("must exists");

    assert_eq!(v.advisories.len(), 1);

    // done

    Ok(())
}

/// Ingest the same document, with an update on the product state.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn change_ps_num_advisories(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = prepare_ps_state_change(ctx).await?;

    // TODO: it changes. but should it?

    assert_ne!(r1.id, r2.id);

    // check info

    let vuln = VulnerabilityService::new(ctx.db.clone());
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", ())
        .await?
        .expect("must exists");

    // FIXME: as we did perform an update, we should not get two advisories, but the same one

    assert_eq!(v.advisories.len(), 1);

    // done

    Ok(())
}

/// Ingest the same document, with an update on the product state.
///
/// This just ensures that ingesting the exact same document doesn't change the state.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn change_ps_list_vulns(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = prepare_ps_state_change(ctx).await?;

    // TODO: it changes. but should it?

    assert_ne!(r1.id, r2.id);

    // check info

    let service = PurlService::new(ctx.db.clone());
    let purls = service
        .purls(Default::default(), Default::default(), ())
        .await?;

    // pkg:rpm/redhat/eap7-bouncycastle@1.76.0-4.redhat_00001.1.el9eap?arch=noarch
    let purl = purls
        .items
        .iter()
        .find(|purl| {
            purl.base.purl.name == "eap7-bouncycastle-util"
                && purl.version.version == "1.76.0-4.redhat_00001.1.el9eap"
        })
        .expect("must find one");

    assert_eq!(
        purl.base.purl,
        Purl {
            ty: "rpm".to_string(),
            namespace: Some("redhat".to_string()),
            name: "eap7-bouncycastle-util".to_string(),
            version: None,
            qualifiers: Default::default(),
        }
    );
    assert_eq!(purl.version.version, "1.76.0-4.redhat_00001.1.el9eap");

    // FIXME: I'd expect the qualifiers to be present, but they aren't.
    /*
    assert_eq!(
        purl.qualifiers.clone().into_iter().collect::<Vec<_>>(),
        vec![("arch".to_string(), "noarch".to_string())]
    );
    */

    // get vuln by purl

    let mut purl = service
        .purl_by_uuid(&purl.head.uuid, ())
        .await?
        .expect("must find something");

    // FIXME: should be 1 I guess

    assert_eq!(purl.advisories.len(), 2);
    purl.advisories
        .sort_unstable_by(|a, b| a.head.modified.cmp(&b.head.modified));
    let adv1 = &purl.advisories[0];
    let adv2 = &purl.advisories[1];

    // FIXME: Getting weird? Same "ID" twice, but wait!

    assert_eq!(adv1.head.identifier, "CVE-2023-33201");
    assert_eq!(adv2.head.identifier, "CVE-2023-33201");

    // now check the details

    // FIXME: same here, instead of having contradicting information, we should have "fixed" now.

    assert_eq!(
        adv1.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2023-33201".to_string(),
                title: None,
                description: None,
                published: None,
                modified: None,
                withdrawn: None,
                discovered: None,
                released: None,
                cwes: vec![],
            },
            status: "affected".to_string(),
            context: Some(StatusContext::Cpe(
                "cpe:/a:redhat:jboss_enterprise_application_platform:7.4:*:el9:*".to_string()
            )),
        }]
    );
    assert_eq!(
        adv2.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2023-33201".to_string(),
                title: None,
                description: None,
                published: None,
                modified: None,
                withdrawn: None,
                discovered: None,
                released: None,
                cwes: vec![],
            },
            status: "fixed".to_string(),
            context: Some(StatusContext::Cpe(
                "cpe:/a:redhat:jboss_enterprise_application_platform:7.4:*:el9:*".to_string()
            )),
        }]
    );

    // done

    Ok(())
}

/// prepare a state with an updated advisory, making a change in the product state section.
async fn prepare_ps_state_change(
    ctx: &TrustifyContext,
) -> anyhow::Result<(IngestResult, IngestResult)> {
    const CVE: &str = "CVE-2023-33201";
    const PRODUCT: &str =
        "9Base-JBEAP-7.4:eap7-bouncycastle-util-0:1.76.0-4.redhat_00001.1.el9eap.noarch";

    twice(
        &ctx,
        |mut csaf| {
            let vulns = csaf.vulnerabilities.as_mut().unwrap();

            let v = vulns
                .iter_mut()
                .find(|v| v.cve.as_deref() == Some(CVE))
                .unwrap();

            let ps = v.product_status.as_mut().unwrap();

            // remove from fixed to known affected

            ps.fixed.as_mut().unwrap().retain(|ps| ps.0 != PRODUCT);
            ps.known_affected
                .as_mut()
                .unwrap()
                .push(ProductIdT(PRODUCT.into()));

            csaf
        },
        |mut csaf| {
            uptick_tracking(&mut csaf);
            csaf.document.tracking.current_release_date += chrono::Duration::days(1);

            let vulns = csaf.vulnerabilities.as_mut().unwrap();

            let v = vulns
                .iter_mut()
                .find(|v| v.cve.as_deref() == Some(CVE))
                .unwrap();

            let ps = v.product_status.as_mut().unwrap();

            // now back to fixed

            ps.known_affected
                .as_mut()
                .unwrap()
                .retain(|ps| ps.0 != PRODUCT);
            ps.fixed.as_mut().unwrap().push(ProductIdT(PRODUCT.into()));

            csaf
        },
    )
    .await
}

/// Ingest a document twice, mutating it using the provided closure.
async fn twice<M1, M2>(
    ctx: &TrustifyContext,
    m1: M1,
    m2: M2,
) -> anyhow::Result<(IngestResult, IngestResult)>
where
    M1: FnOnce(Csaf) -> Csaf,
    M2: FnOnce(Csaf) -> Csaf,
{
    let data = document_bytes("csaf/cve-2023-33201.json").await?;
    let csaf: Csaf = serde_json::from_slice(&data)?;

    let csaf = m1(csaf);

    let result = ctx
        .ingest_read(serde_json::to_vec(&csaf)?.as_slice())
        .await?;

    let csaf = m2(csaf);

    let result2 = ctx
        .ingest_read(serde_json::to_vec(&csaf)?.as_slice())
        .await?;

    Ok((result, result2))
}

/// Uptick the tracking information according to the spec, adding a new revision record,
/// incrementing the main tracking version.
fn uptick_tracking(csaf: &mut Csaf) {
    let current = &csaf.document.tracking.version;

    let next = uptick_version(&current).expect("unable to increment version");

    csaf.document.tracking.version = next.clone();
    csaf.document.tracking.revision_history.push(Revision {
        date: Default::default(),
        legacy_version: None,
        number: next.into(),
        summary: "Updated for test".to_string(),
    });
}

/// Uptick the version by one.
///
/// The version can be either a plain number or a semantic version. We increment by one, considering
/// a major change.
///
/// > Whenever the operator needs to do a new matching run on his asset database (matching the products from the CSAF product tree with deployed products) the MAJOR version is incremented.
fn uptick_version(version: &str) -> anyhow::Result<String> {
    if version.contains('.') {
        let mut version = semver::Version::parse(version)?;
        version.major += 1;
        Ok(version.to_string())
    } else {
        let version = version.parse::<u64>()? + 1;
        Ok(version.to_string())
    }
}
