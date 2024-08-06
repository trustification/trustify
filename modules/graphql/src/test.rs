use std::collections::HashMap;

use crate::RootQuery;
use async_graphql::{EmptyMutation, EmptySubscription, Request, Schema, Variables};
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_module_ingestor::graph::Graph;
use trustify_test_context::TrustifyContext;

const GET_ADVISORY_BY_ID: &str = "
    query AdvisoryById($id: UUID!) {
        getAdvisoryById(id: $id) {
            id
            name
        }
    }
";

const GET_ADVISORIES: &str = "
    query Advisories {
        getAdvisories {
            id
            name
            vulnerabilities {
                id
                title
                published
            }
        }
    }
";

const GET_CVES_BY_SBOM: &str = "
    query CVEsBySbom($id: UUID!) {
        cvesBySbom(id: $id) {
            vulnerabilityId
            status
            packages {
                id
                name
                version
            }
        }
    }
";

const GET_ORGANIZATION_BY_NAME: &str = "
    query Organizations($name: String!) {
        getOrganizationByName(name: $name) {
            id
            name
        }	
    }
";

const GET_SBOM_BY_ID: &str = "
    query SBOMyById($id: UUID!) {
        getSbomById(id: $id) {
            sbomId
            sha256
            authors
        }
    }
";

const GET_SBOM_BY_LABELS: &str = "
    query SBOMyById($labels: Labels!) {
        getSbomById(id: $labels) {
            sbomId
            sha256
            authors
        }
    }
";

const GET_VULNERABILITIES: &str = "
    query V11y {
        getVulnerabilities {
            id
            title
        }
    }
";

const GET_VULNERABILITY_BY_ID: &str = "
    query VulnerabilityById($identifier: String!) {
        getVulnerabilityById(identifier: $identifier) {
            id
            title
            published
        }
    }
";

#[ignore]
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn get_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _results = ctx
        .ingest_documents(["cve/CVE-2021-32714.json", "cve/CVE-2024-29025.json"])
        .await?;

    let graph = ctx.graph.clone();
    let db = ctx.db.clone();
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Graph>(graph)
        .data::<Database>(db)
        .finish();

    let result = schema.execute(Request::new(GET_ADVISORIES)).await;

    let data = result.data.into_json()?;
    let advisories = &data["getAdvisories"];

    assert_eq!(advisories[0]["identifier"], "CVE-2021-32714");
    assert_eq!(advisories[1]["identifier"], "CVE-2024-29025");

    log::debug!("{}", data);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn get_advisory_by_id(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let results = ctx.ingest_documents(["cve/CVE-2024-29025.json"]).await?;

    let graph = ctx.graph.clone();
    let db = ctx.db.clone();
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Graph>(graph)
        .data::<Database>(db)
        .finish();

    let id = results[0].id.clone();
    let result = schema
        .execute(
            Request::new(GET_ADVISORY_BY_ID).variables(Variables::from_json(json!({
               "id": id,
            }))),
        )
        .await;

    let data = result.data.into_json()?;
    let advisory = &data["getAdvisoryById"];

    assert_eq!(advisory["name"], "CVE-2024-29025");

    log::debug!("{}", data);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn get_organization_by_name(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _results = ctx.ingest_documents(["cve/rhsa-2024-2705.json"]).await?;

    let graph = ctx.graph.clone();
    let db = ctx.db.clone();
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Graph>(graph)
        .data::<Database>(db)
        .finish();

    let result = schema
        .execute(
            Request::new(GET_ORGANIZATION_BY_NAME).variables(Variables::from_json(json!({
               "name": "Red Hat Product Security",
            }))),
        )
        .await;
    println!("Result {:?}", result);
    let data = result.data.into_json()?;
    let organization = &data["getOrganizationByName"];

    assert_eq!(organization["name"], "Red Hat Product Security");

    log::debug!("{}", data);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn get_sbom_by_id(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let results = ctx
        .ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
        .await?;
    let sbom_id = results[0].id.clone();

    let graph = ctx.graph.clone();
    let db = ctx.db.clone();
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Graph>(graph)
        .data::<Database>(db)
        .finish();

    let result = schema
        .execute(
            Request::new(GET_SBOM_BY_ID).variables(Variables::from_json(json!({
               "id": sbom_id,
            }))),
        )
        .await;

    let data = result.data.into_json()?;
    let sbom = &data["getSbomById"];
    assert_eq!(
        sbom["sha256"],
        "8f080039c24decc9a066e08fc8f4b7208437536a0bc788d4c76c38c1e1add6e3"
    );

    log::debug!("{}", data);

    Ok(())
}

#[ignore]
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn get_sbom_by_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _results = ctx
        .ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
        .await?;

    let graph = ctx.graph.clone();
    let db = ctx.db.clone();
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Graph>(graph)
        .data::<Database>(db)
        .finish();

    let mut labels: HashMap<String, String> = HashMap::new();
    labels.insert(String::from("type"), String::from("spdx"));

    let result = schema
        .execute(
            Request::new(GET_SBOM_BY_LABELS).variables(Variables::from_json(json!({
               "labels": labels,
            }))),
        )
        .await;

    let data = result.data.into_json()?;
    let sbom = &data["getSbomById"];
    assert_eq!(
        sbom["sha256"],
        "8f080039c24decc9a066e08fc8f4b7208437536a0bc788d4c76c38c1e1add6e3"
    );

    log::debug!("{}", data);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn get_vulnerabilities(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _results = ctx.ingest_documents(["cve/rhsa-2024-2705.json"]).await?;

    let graph = ctx.graph.clone();
    let db = ctx.db.clone();
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Graph>(graph)
        .data::<Database>(db)
        .finish();

    let result = schema.execute(Request::new(GET_VULNERABILITIES)).await;

    let data = result.data.into_json()?;
    let vulnerabilities = &data["getVulnerabilities"];

    assert_eq!(vulnerabilities[0]["id"], "CVE-2024-2700");
    assert_eq!(vulnerabilities[1]["id"], "CVE-2024-29025");

    log::debug!("{}", data);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn get_vulnerability_by_id(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _results = ctx.ingest_documents(["cve/CVE-2024-29025.json"]).await?;

    let graph = ctx.graph.clone();
    let db = ctx.db.clone();
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Graph>(graph)
        .data::<Database>(db)
        .finish();

    let result = schema
        .execute(
            Request::new(GET_VULNERABILITY_BY_ID).variables(Variables::from_json(json!({
               "identifier": "CVE-2024-29025",
            }))),
        )
        .await;

    let data = result.data.into_json()?;
    let vulnerability = &data["getVulnerabilityById"];

    assert_eq!(vulnerability["id"], "CVE-2024-29025");

    log::debug!("{}", data);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn get_cves_by_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let results = ctx
        .ingest_documents([
            "cve/rhsa-2024-2705.json",
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

    let sbom_id = results[1].id.clone();

    let graph = ctx.graph.clone();
    let db = ctx.db.clone();
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Graph>(graph)
        .data::<Database>(db)
        .finish();

    let result = schema
        .execute(
            Request::new(GET_CVES_BY_SBOM).variables(Variables::from_json(json!({
               "id": sbom_id,
            }))),
        )
        .await;

    let data = result.data.into_json()?;
    let cves = &data["cvesBySbom"];

    assert_eq!(cves[0]["vulnerabilityId"], "CVE-2024-2700");
    assert_eq!(cves[0]["status"], "not_affected");

    assert_eq!(cves[1]["vulnerabilityId"], "CVE-2024-29025");
    assert_eq!(cves[1]["status"], "not_affected");

    assert_eq!(cves[2]["vulnerabilityId"], "CVE-2024-2700");
    assert_eq!(cves[2]["status"], "fixed");

    assert_eq!(cves[3]["vulnerabilityId"], "CVE-2024-29025");
    assert_eq!(cves[3]["status"], "fixed");
    assert_eq!(
        cves[3]["packages"][0]["id"],
        "SPDXRef-8ca68978-8302-46cb-b0ea-8912a06428ce"
    );
    assert_eq!(cves[3]["packages"][0]["name"], "netty-codec-http");
    assert_eq!(
        cves[3]["packages"][0]["version"],
        "4.1.100.Final-redhat-00001"
    );

    log::info!("{}", data);

    Ok(())
}
