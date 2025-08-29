#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use crate::sbom::cyclonedx::external::split_uid;
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_common::model::Paginated;
use trustify_module_analysis::{
    config::AnalysisConfig,
    service::{AnalysisService, ComponentReference, QueryOptions},
};
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::{TrustifyContext, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn cdx_prod_comp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_documents([
            "cyclonedx/rh/product_component/example_product_quarkus.json",
            "cyclonedx/rh/product_component/example_component_quarkus.json",
        ])
        .await?;

    let [_prod, _comp] = split_uid(result);

    let _service = SbomService::new(ctx.db.clone());

    // TODO: implement when we have the tools

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn cdx_imageindex_variant(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_documents([
            "cyclonedx/rh/image_index_variants/example_container_index.json",
            "cyclonedx/rh/image_index_variants/example_container_variant_amd64.json",
            "cyclonedx/rh/image_index_variants/example_container_variant_arm64.json",
            "cyclonedx/rh/image_index_variants/example_container_variant_ppc.json",
            "cyclonedx/rh/image_index_variants/example_container_variant_s390x.json",
        ])
        .await?;

    let [index, _amd64, _arm64, _ppc, s390x] = split_uid(result);

    let service = AnalysisService::new(AnalysisConfig::default());
    service.load_all_graphs(&ctx.db).await?;

    let comp_index = service
        .retrieve_single(
            index,
            ComponentReference::Id(
                "ose-openstack-cinder-csi-driver-operator-container_image-index",
            ),
            QueryOptions::descendants(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    let json = serde_json::to_value(comp_index.items)?;

    println!("{json:#?}");

    assert!(json.contains_subset(json!([
        {
            "sbom_id": index,
            "node_id": "ose-openstack-cinder-csi-driver-operator-container_image-index",
            "purl": [
                "pkg:oci/openshift-ose-openstack-cinder-csi-driver-operator@sha256:4e1a8039dfcd2a1ae7672d99be63777b42f9fad3baca5e9273653b447ae72fe8",
            ],
            "descendants": [
                {
                    "sbom_id": index,
                    "node_id": "ose-openstack-cinder-csi-driver-operator-container_s390x",
                    "relationship": "variant",
                    "purl": [
                        "pkg:oci/ose-openstack-cinder-csi-driver-operator@sha256:d3d96f71664efb8c2bd9290b8e1ca9c9b93a54cecb266078c4d954a2e9c05d4d?arch=s390x&os=linux&tag=v4.15.0-202501280037.p0.gd0c2407.assembly.stream.el8",
                    ],
                    "descendants": [
                        {
                            "sbom_id": s390x,
                            "node_id": "ose-openstack-cinder-csi-driver-operator-container_s390x",
                            "relationship": "variant",
                            "purl": [
                                "pkg:oci/ose-openstack-cinder-csi-driver-operator@sha256:d3d96f71664efb8c2bd9290b8e1ca9c9b93a54cecb266078c4d954a2e9c05d4d?arch=s390x&os=linux&tag=v4.15.0-202501280037.p0.gd0c2407.assembly.stream.el8",
                            ],
                        }
                    ]
                }
            ]
        },
    ])));

    Ok(())
}
