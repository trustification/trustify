#![cfg(test)]

use crate::graph::Graph;
use std::convert::TryInto;
use test_context::test_context;
use test_log::test;
use trustify_common::db::test::TrustifyContext;
use trustify_common::db::Transactional;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_common::sbom::SbomLocator;
use trustify_entity::relationship::Relationship;
use trustify_module_search::model::SearchOptions;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn query_sboms(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let system = Graph::new(db);

    let sbom_v1 = system
        .ingest_sbom(
            "http://redhat.com/test.json",
            "8",
            "a",
            (),
            Transactional::None,
        )
        .await?;
    let sbom_v1_again = system
        .ingest_sbom(
            "http://redhat.com/test.json",
            "8",
            "a",
            (),
            Transactional::None,
        )
        .await?;
    let sbom_v2 = system
        .ingest_sbom(
            "http://myspace.com/test.json",
            "9",
            "b",
            (),
            Transactional::None,
        )
        .await?;

    let _other_sbom = system
        .ingest_sbom(
            "http://geocities.com/other.json",
            "10",
            "c",
            (),
            Transactional::None,
        )
        .await?;

    assert_eq!(sbom_v1.sbom.id, sbom_v1_again.sbom.id);
    assert_ne!(sbom_v1.sbom.id, sbom_v2.sbom.id);

    let sboms = system
        .sboms(SearchOptions::default(), Paginated::default(), ())
        .await?;
    assert_eq!(3, sboms.total);

    let sboms = system
        .sboms(
            SearchOptions {
                q: "MySpAcE".to_string(),
                ..Default::default()
            },
            Paginated::default(),
            (),
        )
        .await?;
    assert_eq!(1, sboms.total);

    assert_eq!("http://myspace.com/test.json", sboms.items[0].sbom.location);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn ingest_sboms(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let system = Graph::new(db);

    let sbom_v1 = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "8",
            "a",
            (),
            Transactional::None,
        )
        .await?;
    let sbom_v1_again = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "8",
            "b",
            (),
            Transactional::None,
        )
        .await?;
    let sbom_v2 = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "9",
            "c",
            (),
            Transactional::None,
        )
        .await?;

    let _other_sbom = system
        .ingest_sbom(
            "http://sbom.com/other.json",
            "10",
            "d",
            (),
            Transactional::None,
        )
        .await?;

    assert_eq!(sbom_v1.sbom.id, sbom_v1_again.sbom.id);

    assert_ne!(sbom_v1.sbom.id, sbom_v2.sbom.id);
    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn ingest_and_fetch_sboms_describing_purls(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let system = Graph::new(db);

    let sbom_v1 = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "8",
            "a",
            (),
            Transactional::None,
        )
        .await?;
    let sbom_v2 = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "9",
            "b",
            (),
            Transactional::None,
        )
        .await?;
    let sbom_v3 = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "10",
            "c",
            (),
            Transactional::None,
        )
        .await?;

    sbom_v1
        .ingest_describes_package(
            &"pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    sbom_v2
        .ingest_describes_package(
            &"pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    sbom_v3
        .ingest_describes_package(
            &"pkg://maven/io.quarkus/quarkus-core@1.9.3".try_into()?,
            Transactional::None,
        )
        .await?;

    let found = system
        .locate_sboms(
            SbomLocator::Purl("pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?),
            Transactional::None,
        )
        .await?;

    assert_eq!(2, found.len());
    assert!(found.contains(&sbom_v1));
    assert!(found.contains(&sbom_v2));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn ingest_and_locate_sboms_describing_cpes(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let system = Graph::new(db);

    let sbom_v1 = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "8",
            "a",
            (),
            Transactional::None,
        )
        .await?;
    let sbom_v2 = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "9",
            "b",
            (),
            Transactional::None,
        )
        .await?;
    let sbom_v3 = system
        .ingest_sbom(
            "http://sbom.com/test.json",
            "10",
            "c",
            (),
            Transactional::None,
        )
        .await?;

    sbom_v1
        .ingest_describes_cpe22(
            cpe::uri::Uri::parse("cpe:/a:redhat:quarkus:2.13::el8")?,
            Transactional::None,
        )
        .await?;

    sbom_v2
        .ingest_describes_cpe22(
            cpe::uri::Uri::parse("cpe:/a:redhat:quarkus:2.13::el8")?,
            Transactional::None,
        )
        .await?;

    sbom_v3
        .ingest_describes_cpe22(
            cpe::uri::Uri::parse("cpe:/a:redhat:not-quarkus:2.13::el8")?,
            Transactional::None,
        )
        .await?;

    let found = system
        .locate_sboms(
            SbomLocator::Cpe(cpe::uri::Uri::parse("cpe:/a:redhat:quarkus:2.13::el8")?.into()),
            Transactional::None,
        )
        .await?;

    assert_eq!(2, found.len());
    assert!(found.contains(&sbom_v1));
    assert!(found.contains(&sbom_v2));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn transitive_dependency_of(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let system = Graph::new(db);

    let sbom1 = system
        .ingest_sbom(
            "http://sbomsRus.gov/thing1.json",
            "8675309",
            "a",
            (),
            Transactional::None,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            &"pkg://maven/io.quarkus/transitive-b@1.2.3".try_into()?,
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/transitive-a@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            &"pkg://maven/io.quarkus/transitive-c@1.2.3".try_into()?,
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/transitive-b@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            &"pkg://maven/io.quarkus/transitive-d@1.2.3".try_into()?,
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/transitive-c@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            &"pkg://maven/io.quarkus/transitive-e@1.2.3".try_into()?,
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/transitive-c@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            &"pkg://maven/io.quarkus/transitive-d@1.2.3".try_into()?,
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/transitive-b@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    let _results = sbom1
        .related_packages_transitively(
            &[Relationship::DependencyOf],
            &"pkg://maven/io.quarkus/transitive-a@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn ingest_package_relates_to_package_dependency_of(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let system = Graph::new(db);

    let sbom1 = system
        .ingest_sbom(
            "http://sbomsRus.gov/thing1.json",
            "8675309",
            "a",
            (),
            Transactional::None,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            &"pkg://maven/io.quarkus/quarkus-postgres@1.2.3".try_into()?,
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    let sbom2 = system
        .ingest_sbom(
            "http://sbomsRus.gov/thing2.json",
            "8675308",
            "b",
            (),
            Transactional::None,
        )
        .await?;

    sbom2
        .ingest_package_relates_to_package(
            &"pkg://maven/io.quarkus/quarkus-sqlite@1.2.3".try_into()?,
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    let dependencies = sbom1
        .related_packages(
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    assert_eq!(1, dependencies.len());

    assert_eq!(
        "pkg://maven/io.quarkus/quarkus-postgres@1.2.3",
        Purl::from(dependencies[0].clone()).to_string()
    );

    let dependencies = sbom2
        .related_packages(
            Relationship::DependencyOf,
            &"pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

    assert_eq!(1, dependencies.len());

    assert_eq!(
        "pkg://maven/io.quarkus/quarkus-sqlite@1.2.3",
        Purl::from(dependencies[0].clone()).to_string()
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn sbom_vulnerabilities(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let system = Graph::new(db);

    println!("{:?}", system);

    let sbom = system
        .ingest_sbom(
            "http://sbomsRus.gov/thing1.json",
            "8675309",
            "a",
            (),
            Transactional::None,
        )
        .await?;

    println!("-------------------- A");

    sbom.ingest_describes_package(&"pkg://oci/my-app@1.2.3".try_into()?, Transactional::None)
        .await?;
    println!("-------------------- B");

    sbom.ingest_package_relates_to_package(
        &"pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
        Relationship::DependencyOf,
        &"pkg://oci/my-app@1.2.3".try_into()?,
        Transactional::None,
    )
    .await?;
    println!("-------------------- C");

    sbom.ingest_package_relates_to_package(
        &"pkg://maven/io.quarkus/quarkus-postgres@1.2.3".try_into()?,
        Relationship::DependencyOf,
        &"pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
        Transactional::None,
    )
    .await?;
    println!("-------------------- D");

    sbom.ingest_package_relates_to_package(
        &"pkg://maven/postgres/postgres-driver@1.2.3".try_into()?,
        Relationship::DependencyOf,
        &"pkg://maven/io.quarkus/quarkus-postgres@1.2.3".try_into()?,
        Transactional::None,
    )
    .await?;

    let advisory = system
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/secdata/RHSA-1",
            "7",
            (),
            Transactional::None,
        )
        .await?;

    let advisory_vulnerability = advisory
        .link_to_vulnerability("CVE-00000001", Transactional::None)
        .await?;

    advisory_vulnerability
        .ingest_affected_package_range(
            &"pkg://maven/postgres/postgres-driver".try_into()?,
            "1.1",
            "1.9",
            Transactional::None,
        )
        .await?;

    let assertions = sbom.vulnerability_assertions(Transactional::None).await?;

    assert_eq!(1, assertions.len());

    let affected_purls = assertions
        .keys()
        .map(|e| Purl::from(e.clone()))
        .collect::<Vec<_>>();

    assert_eq!(
        affected_purls[0].to_string(),
        "pkg://maven/postgres/postgres-driver@1.2.3"
    );

    Ok(())
}

/*
#[tokio::test]
async fn ingest_contains_packages() -> Result<(), anyhow::Error> {
    env_logger::builder()
    .filter_level(log::LevelFilter::Info)
    .is_test(true)
    .init();

        let fetch = InnerSystem::for_test("ingest_contains_packages").await?;

        let sbom = fetch
            .ingest_sbom("http://sboms.mobi/something.json", "7", Transactional::None)
            .await?;

        let contains1 = sbom
            .ingest_contains_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let contains2 = sbom
            .ingest_contains_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let contains3 = sbom
            .ingest_contains_package(
                "pkg://maven/io.quarkus/quarkus-addons@1.2.3",
                Transactional::None,
            )
            .await?;

        assert_eq!(
            contains1.sbom_contains_package.qualified_package_id,
            contains2.sbom_contains_package.qualified_package_id
        );
        assert_ne!(
            contains1.sbom_contains_package.qualified_package_id,
            contains3.sbom_contains_package.qualified_package_id
        );

        let mut contains = sbom.contains_packages(Transactional::None).await?;

        assert_eq!(2, contains.len());

        let contains: Vec<_> = contains.drain(0..).map(Purl::from).collect();

        assert!(contains.contains(&Purl::from("pkg://maven/io.quarkus/quarkus-core@1.2.3")));
        assert!(contains.contains(&Purl::from("pkg://maven/io.quarkus/quarkus-addons@1.2.3")));

        Ok(())
    }
     */

/*

#[tokio::test]
async fn ingest_and_fetch_sbom_packages() -> Result<(), anyhow::Error> {
    /*
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .init();

     */
    let fetch = InnerSystem::for_test("ingest_and_fetch_sbom_packages").await?;

    let sbom_v1 = fetch.ingest_sbom("http://sbom.com/test.json", "8").await?;
    let sbom_v2 = fetch.ingest_sbom("http://sbom.com/test.json", "9").await?;
    let sbom_v3 = fetch
        .ingest_sbom("http://sbom.com/test.json", "10")
        .await?;

    sbom_v1
        .ingest_sbom_dependency("pkg://maven/io.quarkus/taco@1.2.3", Transactional::None)
        .await?;

    sbom_v1
        .ingest_package_dependency(
            "pkg://maven/io.quarkus/foo@1.2.3",
            "pkg://maven/io.quarkus/baz@1.2.3",
            Transactional::None,
        )
        .await?;

    sbom_v2
        .ingest_package_dependency(
            "pkg://maven/io.quarkus/foo@1.2.3",
            "pkg://maven/io.quarkus/bar@1.2.3",
            Transactional::None,
        )
        .await?;

    let sbom_packages = sbom_v1.all_packages(Transactional::None).await?;
    assert_eq!(3, sbom_packages.len());

    for sbom_package in sbom_packages {
        let _sboms = sbom_package
            .package
            .sboms_containing(Transactional::None)
            .await?;
    }

    Ok(())
}

 */
