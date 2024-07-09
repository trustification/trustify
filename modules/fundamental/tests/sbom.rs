#![allow(clippy::expect_used)]
#![allow(dead_code)]

mod spdx {
    use super::*;
    use std::convert::Infallible;
    use test_context::futures::stream;
    use test_context::test_context;
    use test_log::test;
    use tracing::instrument;
    use trustify_common::db::Transactional;
    use trustify_entity::relationship::Relationship;
    use trustify_module_fundamental::sbom::model::{SbomPackage, Which};
    use trustify_module_fundamental::sbom::service::SbomService;
    use trustify_module_ingestor::graph::Graph;
    use trustify_module_ingestor::service::{Format, IngestorService};
    use trustify_module_storage::service::fs::FileSystemBackend;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[instrument]
    #[test(tokio::test)]
    async fn parse_spdx_quarkus(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        test_with_spdx(
        ctx,
        "quarkus-bom-2.13.8.Final-redhat-00004.json",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
                .await?;
            log::debug!("{:#?}", described);
            assert_eq!(1, described.items.len());
            let first = &described.items[0];
            assert_eq!(
                &SbomPackage {
                    id: "SPDXRef-b52acd7c-3a3f-441e-aef0-bbdaa1ec8acf".into(),
                    name: "quarkus-bom".into(),
                    version: Some("2.13.8.Final-redhat-00004".to_string()),
                    purl: vec![
                        "pkg://maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom".into()
                    ],
                    cpe: vec!["cpe:/a:redhat:quarkus:2.13:*:el8:*".to_string()],
                },
                first
            );

            let contains = service
                .related_packages(
                    sbom.sbom.sbom_id,
                    Relationship::ContainedBy,
                    first,
                    Transactional::None,
                )
                .await?;

            log::debug!("{}", contains.len());

            assert!(contains.len() > 500);

            Ok(())
        },
    ).await
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_parse_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        test_with_spdx(
            ctx,
            "ubi9-9.2-755.1697625012.json",
            |WithContext { service, sbom, .. }| async move {
                let described = service
                    .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
                    .await?;

                assert_eq!(1, described.total);
                let first = &described.items[0];

                let contains = service
                    .fetch_related_packages(
                        sbom.sbom.sbom_id,
                        Default::default(),
                        Default::default(),
                        Which::Right,
                        first,
                        Some(Relationship::ContainedBy),
                        (),
                    )
                    .await?
                    .items;

                log::debug!("{}", contains.len());

                assert!(contains.len() > 500);

                Ok(())
            },
        )
        .await
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_spdx_broken_refs(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let data = ctx.document_bytes("spdx/broken-refs.json").await?;
        let (storage, _tmp) = FileSystemBackend::for_test().await?;
        let ingestor = IngestorService::new(graph, storage);
        let sbom = SbomService::new(db.clone());

        let err = ingestor
            .ingest(
                ("source", "test"),
                None,
                Format::sbom_from_bytes(&data)?,
                stream::iter([Ok::<_, Infallible>(data)]),
            )
            .await
            .expect_err("must not ingest");

        assert_eq!(
            err.to_string(),
            "Invalid SPDX reference: SPDXRef-0068e307-de91-4e82-b407-7a41217f9758"
        );

        let result = sbom
            .fetch_sboms(Default::default(), Default::default(), (), ())
            .await?;

        // there must be no traces, everything must be rolled back
        assert_eq!(result.total, 0);

        Ok(())
    }

    mod perf {
        use super::*;
        use test_context::test_context;
        use test_log::test;
        use tracing::instrument;
        use trustify_common::{db::Transactional, model::Paginated};
        use trustify_module_fundamental::sbom::model::SbomPackage;
        use trustify_test_context::TrustifyContext;

        #[test_context(TrustifyContext)]
        #[test(tokio::test)]
        #[instrument]
        async fn ingest_spdx_medium(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
            test_with_spdx(
                ctx,
                "openshift-container-storage-4.8.z.json.xz",
                |WithContext { service, sbom, .. }| async move {
                    let described = service
                        .describes_packages(sbom.sbom.sbom_id, Default::default(), ())
                        .await?;

                    log::debug!("{:#?}", described);
                    assert_eq!(1, described.items.len());
                    assert_eq!(
                        described.items[0],
                        SbomPackage {
                            id: "SPDXRef-5fbf9e8d-2f8f-4cfe-a145-b69a1f7d73cc".to_string(),
                            name: "RHEL-8-RHOCS-4.8".to_string(),
                            version: Some("4.8.z".to_string()),
                            purl: vec![],
                            cpe: vec![
                                "cpe:/a:redhat:openshift_container_storage:4.8:*:el8:*".into()
                            ],
                        }
                    );

                    let packages = service
                        .fetch_sbom_packages(
                            sbom.sbom.sbom_id,
                            Default::default(),
                            Paginated {
                                offset: 0,
                                limit: 1,
                            },
                            (),
                        )
                        .await?;
                    assert_eq!(1, packages.items.len());
                    assert_eq!(7994, packages.total);

                    Ok(())
                },
            )
            .await
        }

        // ignore because it's a slow slow slow test.
        #[test_context(TrustifyContext)]
        #[ignore]
        #[test(tokio::test)]
        async fn ingest_spdx_large(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
            test_with_spdx(
                ctx,
                "openshift-4.13.json.xz",
                |WithContext { service, sbom, .. }| async move {
                    let described = service
                        .describes_packages(
                            sbom.sbom.sbom_id,
                            Default::default(),
                            Transactional::None,
                        )
                        .await?;
                    log::debug!("{:#?}", described);
                    assert_eq!(1, described.items.len());

                    let first = &described.items[0];
                    assert_eq!(3, first.cpe.len());

                    Ok(())
                },
            )
            .await
        }

        /// A test having a lot of CPEs to ingest
        #[test_context(TrustifyContext)]
        #[test(tokio::test)]
        #[instrument]
        async fn ingest_spdx_medium_cpes(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
            test_with_spdx(
                ctx,
                "rhel-br-9.2.0.json.xz",
                |WithContext { service, sbom, .. }| async move {
                    let described = service
                        .describes_packages(sbom.sbom.sbom_id, Default::default(), ())
                        .await?;

                    log::debug!("{:#?}", described);
                    assert_eq!(1, described.items.len());
                    assert_eq!(
                        described.items[0],
                        SbomPackage {
                            id: "SPDXRef-59713547-8cb2-4cf4-a310-1e28c7a7b35a".to_string(),
                            name: "RHEL-BR-9.2.0".to_string(),
                            version: Some("9.2.0".to_string()),
                            purl: vec![],
                            cpe: vec![],
                        }
                    );

                    let packages = service
                        .fetch_sbom_packages(
                            sbom.sbom.sbom_id,
                            Default::default(),
                            Paginated {
                                offset: 0,
                                limit: 1,
                            },
                            (),
                        )
                        .await?;
                    assert_eq!(1, packages.items.len());
                    assert_eq!(50668, packages.total);

                    Ok(())
                },
            )
            .await
        }
    }

    /// remove all relationships having broken references
    fn fix_spdx_rels(mut spdx: SPDX) -> SPDX {
        let mut ids = spdx
            .package_information
            .iter()
            .map(|p| &p.package_spdx_identifier)
            .collect::<HashSet<_>>();

        ids.insert(&spdx.document_creation_information.spdx_identifier);

        spdx.relationships.retain(|rel| {
            let r = ids.contains(&rel.spdx_element_id) && ids.contains(&rel.related_spdx_element);
            if !r {
                log::warn!(
                    "Dropping - left: {}, rel: {:?}, right: {}",
                    rel.spdx_element_id,
                    rel.relationship_type,
                    rel.related_spdx_element
                );
            }
            r
        });

        spdx
    }

    #[instrument(skip(ctx, f))]
    pub async fn test_with_spdx<F, Fut>(
        ctx: &TrustifyContext,
        sbom: &str,
        f: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce(WithContext) -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        test_with(
            ctx,
            sbom,
            |data| {
                let (sbom, _) = parse_spdx(&Discard, data)?;
                Ok(fix_spdx_rels(sbom))
            },
            |ctx, sbom, tx| {
                Box::pin(async move {
                    ctx.ingest_spdx(sbom.clone(), &Discard, &tx).await?;
                    Ok(())
                })
            },
            |sbom| sbom::spdx::Information(sbom).into(),
            f,
        )
        .await
    }
}

mod cyclonedx {
    use super::*;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::Transactional;
    use trustify_common::model::Paginated;
    use trustify_module_fundamental::sbom::model::SbomPackage;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_parse_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        test_with_cyclonedx(
            ctx,
            "zookeeper-3.9.2-cyclonedx.json",
            |WithContext { service, sbom, .. }| async move {
                let described = service
                    .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
                    .await?;

                assert_eq!(
                    described.items,
                    vec![SbomPackage {
                        id: "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string(),
                        name: "zookeeper".to_string(),
                        version: Some("3.9.2".to_string()),
                        purl: vec![
                            "pkg://maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string()
                        ],
                        cpe: vec![],
                    }]
                );

                let packages = service
                    .fetch_sbom_packages(
                        sbom.sbom.sbom_id,
                        Default::default(),
                        Paginated {
                            offset: 0,
                            limit: 1,
                        },
                        (),
                    )
                    .await?;

                log::debug!("{:?}", packages);

                assert_eq!(41, packages.total);

                Ok(())
            },
        )
        .await
    }

    #[instrument(skip(ctx, f))]
    pub async fn test_with_cyclonedx<F, Fut>(
        ctx: &TrustifyContext,
        sbom: &str,
        f: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce(WithContext) -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        test_with(
            ctx,
            sbom,
            |data| Ok(Bom::parse_from_json(data)?),
            |ctx, sbom, tx| Box::pin(async move { ctx.ingest_cyclonedx(sbom.clone(), &tx).await }),
            |sbom| sbom::cyclonedx::Information(sbom).into(),
            f,
        )
        .await
    }
}

mod graph {
    use std::convert::TryInto;
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::Transactional;
    use trustify_common::hashing::Digests;
    use trustify_common::purl::Purl;
    use trustify_common::sbom::SbomLocator;
    use trustify_entity::relationship::Relationship;
    use trustify_module_fundamental::sbom::service::SbomService;
    use trustify_module_ingestor::graph::Graph;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_sboms(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        let sbom_v1 = system
            .ingest_sbom(
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("8"),
                "a",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v1_again = system
            .ingest_sbom(
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("8"),
                "b",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v2 = system
            .ingest_sbom(
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("9"),
                "c",
                (),
                Transactional::None,
            )
            .await?;

        let _other_sbom = system
            .ingest_sbom(
                ("source", "http://sbom.com/other.json"),
                &Digests::digest("10"),
                "d",
                (),
                Transactional::None,
            )
            .await?;

        assert_eq!(sbom_v1.sbom.sbom_id, sbom_v1_again.sbom.sbom_id);

        assert_ne!(sbom_v1.sbom.sbom_id, sbom_v2.sbom.sbom_id);
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
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("8"),
                "a",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v2 = system
            .ingest_sbom(
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("9"),
                "b",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v3 = system
            .ingest_sbom(
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("10"),
                "c",
                (),
                Transactional::None,
            )
            .await?;

        sbom_v1
            .ingest_describes_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        sbom_v2
            .ingest_describes_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        sbom_v3
            .ingest_describes_package(
                "pkg://maven/io.quarkus/quarkus-core@1.9.3".try_into()?,
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
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("8"),
                "a",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v2 = system
            .ingest_sbom(
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("9"),
                "b",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v3 = system
            .ingest_sbom(
                ("source", "http://sbom.com/test.json"),
                &Digests::digest("10"),
                "c",
                (),
                Transactional::None,
            )
            .await?;

        sbom_v1
            .ingest_describes_cpe22(
                "cpe:/a:redhat:quarkus:2.13::el8".parse()?,
                Transactional::None,
            )
            .await?;

        sbom_v2
            .ingest_describes_cpe22(
                "cpe:/a:redhat:quarkus:2.13::el8".parse()?,
                Transactional::None,
            )
            .await?;

        sbom_v3
            .ingest_describes_cpe22(
                "cpe:/a:redhat:not-quarkus:2.13::el8".parse()?,
                Transactional::None,
            )
            .await?;

        let found = system
            .locate_sboms(
                SbomLocator::Cpe("cpe:/a:redhat:quarkus:2.13::el8".parse()?),
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
                ("source", "http://sbomsRus.gov/thing1.json"),
                &Digests::digest("8675309"),
                "a",
                (),
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                Purl::from_str("pkg://maven/io.quarkus/transitive-b@1.2.3")?,
                Relationship::DependencyOf,
                Purl::from_str("pkg://maven/io.quarkus/transitive-a@1.2.3")?,
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                Purl::from_str("pkg://maven/io.quarkus/transitive-c@1.2.3")?,
                Relationship::DependencyOf,
                Purl::from_str("pkg://maven/io.quarkus/transitive-b@1.2.3")?,
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                Purl::from_str("pkg://maven/io.quarkus/transitive-d@1.2.3")?,
                Relationship::DependencyOf,
                Purl::from_str("pkg://maven/io.quarkus/transitive-c@1.2.3")?,
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                Purl::from_str("pkg://maven/io.quarkus/transitive-e@1.2.3")?,
                Relationship::DependencyOf,
                Purl::from_str("pkg://maven/io.quarkus/transitive-c@1.2.3")?,
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                Purl::from_str("pkg://maven/io.quarkus/transitive-d@1.2.3")?,
                Relationship::DependencyOf,
                Purl::from_str("pkg://maven/io.quarkus/transitive-b@1.2.3")?,
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
        let system = Graph::new(db.clone());
        let fetch = SbomService::new(db);

        let sbom1 = system
            .ingest_sbom(
                ("source", "http://sbomsRus.gov/thing1.json"),
                &Digests::digest("8675309"),
                "a",
                (),
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                Purl::from_str("pkg://maven/io.quarkus/quarkus-postgres@1.2.3")?,
                Relationship::DependencyOf,
                Purl::from_str("pkg://maven/io.quarkus/quarkus-core@1.2.3")?,
                Transactional::None,
            )
            .await?;

        let sbom2 = system
            .ingest_sbom(
                ("source", "http://sbomsRus.gov/thing2.json"),
                &Digests::digest("8675308"),
                "b",
                (),
                Transactional::None,
            )
            .await?;

        sbom2
            .ingest_package_relates_to_package(
                Purl::from_str("pkg://maven/io.quarkus/quarkus-sqlite@1.2.3")?,
                Relationship::DependencyOf,
                Purl::from_str("pkg://maven/io.quarkus/quarkus-core@1.2.3")?,
                Transactional::None,
            )
            .await?;

        let dependencies = fetch
            .related_packages(
                sbom1.sbom.sbom_id,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        assert_eq!(1, dependencies.len());

        assert_eq!(
            vec!["pkg://maven/io.quarkus/quarkus-postgres@1.2.3"],
            dependencies[0].purl
        );

        let dependencies = fetch
            .related_packages(
                sbom2.sbom.sbom_id,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        assert_eq!(1, dependencies.len());

        assert_eq!(
            vec!["pkg://maven/io.quarkus/quarkus-sqlite@1.2.3"],
            dependencies[0].purl
        );

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn sbom_vulnerabilities(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        log::debug!("{:?}", system);

        let sbom = system
            .ingest_sbom(
                ("source", "http://sbomsRus.gov/thing1.json"),
                &Digests::digest("8675309"),
                "a",
                (),
                Transactional::None,
            )
            .await?;

        log::debug!("-------------------- A");

        sbom.ingest_describes_package("pkg://oci/my-app@1.2.3".try_into()?, Transactional::None)
            .await?;
        log::debug!("-------------------- B");

        sbom.ingest_package_relates_to_package(
            Purl::from_str("pkg://maven/io.quarkus/quarkus-core@1.2.3")?,
            Relationship::DependencyOf,
            Purl::from_str("pkg://oci/my-app@1.2.3")?,
            Transactional::None,
        )
        .await?;
        log::debug!("-------------------- C");

        sbom.ingest_package_relates_to_package(
            Purl::from_str("pkg://maven/io.quarkus/quarkus-postgres@1.2.3")?,
            Relationship::DependencyOf,
            Purl::from_str("pkg://maven/io.quarkus/quarkus-core@1.2.3")?,
            Transactional::None,
        )
        .await?;
        log::debug!("-------------------- D");

        sbom.ingest_package_relates_to_package(
            Purl::from_str("pkg://maven/postgres/postgres-driver@1.2.3")?,
            Relationship::DependencyOf,
            Purl::from_str("pkg://maven/io.quarkus/quarkus-postgres@1.2.3")?,
            Transactional::None,
        )
        .await?;

        let advisory = system
            .ingest_advisory(
                "RHSA-1",
                ("source", "http://redhat.com/secdata/RHSA-1"),
                &Digests::digest("7"),
                (),
                Transactional::None,
            )
            .await?;

        let _advisory_vulnerability = advisory
            .link_to_vulnerability("CVE-00000001", None, Transactional::None)
            .await?;

        Ok(())
    }
}

mod reingest {
    use bytes::Bytes;
    use serde_json::Value;
    use std::str::FromStr;
    use test_context::futures::stream;
    use test_context::test_context;
    use test_log::test;
    use tracing::instrument;
    use trustify_common::db::query::Query;
    use trustify_common::model::Paginated;
    use trustify_common::purl::Purl;
    use trustify_module_fundamental::sbom::service::SbomService;
    use trustify_module_ingestor::graph::Graph;
    use trustify_module_ingestor::service::{Format, IngestorService};
    use trustify_module_storage::service::fs::FileSystemBackend;
    use trustify_test_context::TrustifyContext;

    /// We re-ingest two versions of the same quarkus SBOM. However, as the quarkus SBOM doesn't have
    /// anything in common other than the filename (which doesn't matter), these are considered two
    /// different SBOMs.
    #[test_context(TrustifyContext)]
    #[instrument]
    #[test(tokio::test)]
    async fn quarkus(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let (storage, _tmp) = FileSystemBackend::for_test().await?;
        let sbom = SbomService::new(db.clone());
        let ingest = IngestorService::new(graph, storage);

        // ingest the first version
        let result1 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json")
                    .await?,
            )
            .await?;

        assert_eq!(result1.document_id, "https://access.redhat.com/security/data/sbom/beta/spdx/quarkus-bom-b52acd7c-3a3f-441e-aef0-bbdaa1ec8acf");

        // ingest the second version
        let result2 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("quarkus/v2/quarkus-bom-2.13.8.Final-redhat-00004.json")
                    .await?,
            )
            .await?;

        assert_eq!(
        result2.document_id,
        "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-2.13.8.Final-redhat-00004"
    );

        // now start testing

        assert_ne!(result1.id, result2.id);

        let mut sbom1 = sbom
            .fetch_sbom(result1.id, ())
            .await?
            .expect("v1 must be found");
        log::info!("SBOM1: {sbom1:?}");

        let mut sbom2 = sbom
            .fetch_sbom(result2.id, ())
            .await?
            .expect("v2 must be found");
        log::info!("SBOM2: {sbom2:?}");

        // both sboms have different names

        assert_eq!(sbom1.name, "quarkus-bom");
        assert_eq!(sbom2.name, "quarkus-bom-2.13.8.Final-redhat-00004");
        assert_eq!(sbom1.described_by.len(), 1);
        assert_eq!(sbom2.described_by.len(), 1);

        // clear the ID as that one will be different

        sbom1.described_by[0].id = "".into();
        sbom2.described_by[0].id = "".into();

        assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

        // but both sboms can be found by the same purl

        let purl = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom";

        let sboms = sbom
            .find_related_sboms(
                Purl::from_str(purl).expect("must parse").qualifier_uuid(),
                Paginated::default(),
                Query::default(),
                (),
            )
            .await?;

        assert_eq!(sboms.total, 2);

        // done

        Ok(())
    }

    /// Re-ingest two versions of nhc. They to have the same name and mostly the same name and
    /// document id/namespace. However, they still get ingested as two different SBOMs.
    #[test_context(TrustifyContext)]
    #[instrument]
    #[test(tokio::test)]
    async fn nhc(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let (storage, _tmp) = FileSystemBackend::for_test().await?;
        let sbom = SbomService::new(db.clone());
        let ingest = IngestorService::new(graph, storage);

        // ingest the first version
        let result1 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("nhc/v1/nhc-0.4.z.json.xz").await?,
            )
            .await?;

        assert_eq!(
            result1.document_id,
            "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
        );

        // ingest the second version
        let result2 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("nhc/v2/nhc-0.4.z.json.xz").await?,
            )
            .await?;

        assert_eq!(
            result2.document_id,
            "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
        );

        // now start testing

        assert_ne!(result1.id, result2.id);

        let mut sbom1 = sbom
            .fetch_sbom(result1.id, ())
            .await?
            .expect("v1 must be found");
        log::info!("SBOM1: {sbom1:?}");

        let mut sbom2 = sbom
            .fetch_sbom(result2.id, ())
            .await?
            .expect("v2 must be found");
        log::info!("SBOM2: {sbom2:?}");

        // both sboms have the same name

        assert_eq!(sbom1.name, "RHWA-NHC-0.4-RHEL-8");
        assert_eq!(sbom2.name, "RHWA-NHC-0.4-RHEL-8");
        assert_eq!(sbom1.described_by.len(), 1);
        assert_eq!(sbom2.described_by.len(), 1);

        // clear the ID as that one will be different

        sbom1.described_by[0].id = "".into();
        sbom2.described_by[0].id = "".into();

        assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

        // done

        Ok(())
    }

    /// Re-ingest the same version of nhc twice.
    #[test_context(TrustifyContext)]
    #[instrument]
    #[test(tokio::test)]
    async fn nhc_same(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let (storage, _tmp) = FileSystemBackend::for_test().await?;
        let sbom = SbomService::new(db.clone());
        let ingest = IngestorService::new(graph, storage);

        // ingest the first version

        let result1 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("nhc/v1/nhc-0.4.z.json.xz").await?,
            )
            .await?;

        assert_eq!(
            result1.document_id,
            "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
        );

        // ingest the same version again

        let result2 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("nhc/v1/nhc-0.4.z.json.xz").await?,
            )
            .await?;

        assert_eq!(
            result2.document_id,
            "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
        );

        // now start testing

        // in this case, we get the same ID, as the digest of the content is the same

        assert_eq!(result1.id, result2.id);

        let mut sbom1 = sbom
            .fetch_sbom(result1.id, ())
            .await?
            .expect("v1 must be found");
        log::info!("SBOM1: {sbom1:?}");

        let mut sbom2 = sbom
            .fetch_sbom(result2.id, ())
            .await?
            .expect("v2 must be found");
        log::info!("SBOM2: {sbom2:?}");

        // both sboms have the same name

        assert_eq!(sbom1.name, "RHWA-NHC-0.4-RHEL-8");
        assert_eq!(sbom2.name, "RHWA-NHC-0.4-RHEL-8");
        assert_eq!(sbom1.described_by.len(), 1);
        assert_eq!(sbom2.described_by.len(), 1);

        // clear the ID as that one will be different

        sbom1.described_by[0].id = "".into();
        sbom2.described_by[0].id = "".into();

        assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

        // done

        Ok(())
    }

    /// Re-ingest the same version of nhc twice, but reformat the second one.
    #[test_context(TrustifyContext)]
    #[instrument]
    #[test(tokio::test)]
    async fn nhc_same_content(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let (storage, _tmp) = FileSystemBackend::for_test().await?;
        let sbom = SbomService::new(db.clone());
        let ingest = IngestorService::new(graph, storage);

        // ingest the first version

        let result1 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("nhc/v1/nhc-0.4.z.json.xz").await?,
            )
            .await?;

        assert_eq!(
            result1.document_id,
            "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
        );

        // ingest the second version

        let result2 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                stream::once({
                    // re-serialize file (non-pretty)
                    let json: Value = serde_json::from_slice(
                        &ctx.document_bytes("nhc/v1/nhc-0.4.z.json.xz").await?,
                    )?;

                    let result = serde_json::to_vec(&json).map(Bytes::from);

                    async { result }
                }),
            )
            .await?;

        assert_eq!(
            result2.document_id,
            "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
        );

        // now start testing

        // in this case, we get a different ID, as the digest doesn't match

        assert_ne!(result1.id, result2.id);

        let mut sbom1 = sbom
            .fetch_sbom(result1.id, ())
            .await?
            .expect("v1 must be found");
        log::info!("SBOM1: {sbom1:?}");

        let mut sbom2 = sbom
            .fetch_sbom(result2.id, ())
            .await?
            .expect("v2 must be found");
        log::info!("SBOM2: {sbom2:?}");

        // both sboms have the same name

        assert_eq!(sbom1.name, "RHWA-NHC-0.4-RHEL-8");
        assert_eq!(sbom2.name, "RHWA-NHC-0.4-RHEL-8");
        assert_eq!(sbom1.described_by.len(), 1);
        assert_eq!(sbom2.described_by.len(), 1);

        // clear the ID as that one will be different

        sbom1.described_by[0].id = "".into();
        sbom2.described_by[0].id = "".into();

        assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

        // done

        Ok(())
    }

    /// Run syft twice on the same container.
    ///
    /// This should be the same SBOM, as it's built from exactly the same container. However, conforming
    /// to the SPDX spec, the document gets a new "document namespace".
    #[test_context(TrustifyContext)]
    #[instrument]
    #[test(tokio::test)]
    async fn syft_rerun(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());
        let (storage, _tmp) = FileSystemBackend::for_test().await?;
        let sbom = SbomService::new(db.clone());
        let ingest = IngestorService::new(graph, storage);

        // ingest the first version

        let result1 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("syft-ubi-example/v1.json.xz").await?,
            )
            .await?;

        assert_eq!(
        result1.document_id,
        "https://anchore.com/syft/image/registry.access.redhat.com/ubi9/ubi-f41e17d4-e739-4d33-ab2e-48c95b856220"
    );

        // ingest the second version

        let result2 = ingest
            .ingest(
                ("source", "test"),
                None,
                Format::SPDX,
                ctx.document_stream("syft-ubi-example/v2.json.xz").await?,
            )
            .await?;

        assert_eq!(
        result2.document_id,
        "https://anchore.com/syft/image/registry.access.redhat.com/ubi9/ubi-768a701e-12fb-4ed1-a03b-463b784b01bf"
    );

        // now start testing

        // in this case, we get the same ID, as the digest of the content is the same

        assert_ne!(result1.id, result2.id);

        let mut sbom1 = sbom
            .fetch_sbom(result1.id, ())
            .await?
            .expect("v1 must be found");
        log::info!("SBOM1: {sbom1:?}");

        let mut sbom2 = sbom
            .fetch_sbom(result2.id, ())
            .await?
            .expect("v2 must be found");
        log::info!("SBOM2: {sbom2:?}");

        // both sboms have the same name

        assert_eq!(sbom1.name, "registry.access.redhat.com/ubi9/ubi");
        assert_eq!(sbom2.name, "registry.access.redhat.com/ubi9/ubi");
        assert_eq!(sbom1.described_by.len(), 1);
        assert_eq!(sbom2.described_by.len(), 1);

        // clear the ID as that one will be different

        sbom1.described_by[0].id = "".into();
        sbom2.described_by[0].id = "".into();

        assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

        // done

        Ok(())
    }
}

use cyclonedx_bom::prelude::Bom;
use spdx_rs::models::SPDX;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;
use tracing::{info_span, instrument, Instrument};
use trustify_common::db::{Database, Transactional};
use trustify_common::hashing::Digests;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_ingestor::graph::{
    sbom::{self, spdx::parse_spdx, SbomContext, SbomInformation},
    Graph,
};
use trustify_module_ingestor::service::Discard;
use trustify_test_context::TrustifyContext;

pub struct WithContext {
    pub sbom: SbomContext,
    pub db: Database,
    pub graph: Graph,
    pub service: SbomService,
}

#[instrument(skip(ctx, p, i, c, f))]
pub async fn test_with<B, P, I, C, F, FFut>(
    ctx: &TrustifyContext,
    sbom: &str,
    p: P,
    i: I,
    c: C,
    f: F,
) -> anyhow::Result<()>
where
    P: FnOnce(&[u8]) -> anyhow::Result<B>,
    for<'a> I: FnOnce(
        &'a SbomContext,
        B,
        &'a Transactional,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>>,
    C: FnOnce(&B) -> SbomInformation,
    F: FnOnce(WithContext) -> FFut,
    FFut: Future<Output = anyhow::Result<()>>,
{
    // The `ctx` must live until the end of this function. Otherwise, it will tear down the database
    // while we're testing. So we take the `db` and offer it to the test, but we hold on the `ctx`
    // instance until that test returns.

    let db = &ctx.db;
    let graph = Graph::new(db.clone());
    let service = SbomService::new(db.clone());

    let start = Instant::now();
    let sbom = info_span!("parse json")
        .in_scope(|| async {
            let bytes = ctx.document_bytes(sbom).await?;
            p(&bytes[..])
        })
        .await?;

    let parse_time = start.elapsed();

    let tx = graph.transaction().await?;

    let start = Instant::now();
    let ctx = graph
        .ingest_sbom(
            ("source", "test.com/my-sbom.json"),
            &Digests::digest("10"),
            "document-id",
            c(&sbom),
            &tx,
        )
        .await?;
    let ingest_time_1 = start.elapsed();

    let start = Instant::now();
    i(&ctx, sbom, &tx).await?;
    let ingest_time_2 = start.elapsed();

    // commit

    let start = Instant::now();
    tx.commit().await?;
    let commit_time = start.elapsed();

    // now test

    let start = Instant::now();
    f(WithContext {
        sbom: ctx,
        db: db.clone(),
        graph,
        service,
    })
    .instrument(info_span!("assert"))
    .await?;
    let test_time = start.elapsed();

    // log durations

    log::info!("parse: {}", humantime::Duration::from(parse_time));
    log::info!("ingest 1: {}", humantime::Duration::from(ingest_time_1));
    log::info!("ingest 2: {}", humantime::Duration::from(ingest_time_2));
    log::info!("commit: {}", humantime::Duration::from(commit_time));
    log::info!("test: {}", humantime::Duration::from(test_time));

    Ok(())
}
