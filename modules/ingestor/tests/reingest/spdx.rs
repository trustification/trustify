#![allow(clippy::expect_used)]

use anyhow::bail;
use sea_orm::EntityTrait;
use test_context::test_context;
use test_log::test;
use trustify_common::{cpe::Cpe, id::Id};
use trustify_entity::{cpe::CpeDto, sbom, extracted_licensing_infos, license};
use trustify_module_ingestor::graph::sbom::ExtratedLicensingInfo;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::TrustifyContext;
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    async fn assert(ctx: &TrustifyContext, result: IngestResult) -> anyhow::Result<()> {
        let Id::Uuid(id) = result.id else {
            bail!("must be an id")
        };
        let sbom = ctx
            .graph
            .get_sbom_by_id(id, &ctx.db)
            .await?
            .expect("must be found");

        // check CPEs

        let cpes = sbom.describes_cpe22s(&ctx.db).await?;
        assert_eq!(
            cpes.into_iter()
                .map(|cpe| CpeDto::from(cpe.cpe))
                .filter_map(|cpe| Cpe::try_from(cpe).ok())
                .collect::<Vec<_>>(),
            vec![]
        );

        // check purls

        let purls = sbom.describes_purls(&ctx.db).await?;
        assert_eq!(
            purls
                .into_iter()
                .map(|purl| purl.qualified_package.id)
                .collect::<Vec<_>>(),
            vec![]
        );

        // get product

        let product = sbom
            .get_product(&ctx.db)
            .await?
            .expect("must have a product");
        assert_eq!(product.product.product.name, "quarkus-bom");

        let products = ctx.graph.get_products(&ctx.db).await?;
        assert_eq!(products.len(), 1);

        // get orgs, expect one

        let orgs = ctx.graph.get_organizations(&ctx.db).await?;
        assert_eq!(orgs.len(), 1);

        // get all sboms, expect one

        let sboms = ctx
            .graph
            .locate_many_sboms(sbom::Entity::find(), &ctx.db)
            .await?;

        assert_eq!(sboms.len(), 1);

        // done

        Ok(())
    }

    // ingest once

    let result = ctx.ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json").await?;
    let resul: Vec<extracted_licensing_infos::Model> = extracted_licensing_infos::Entity::find().all(&ctx.db).await?;

   for m in resul {

       println!("{}", format!("id = {} sbom_id ={} licenseid ={} extracted_text={}",m.id, m.sbom_id, m.licenseId,m.extracted_text));
   }

    let resul: Vec<license::Model> = license::Entity::find().all(&ctx.db).await?;

    for m in resul {

        println!("{}", format!("id = {} license_id ={} license_ref_id ={:?} license_type= {}",m.id, m.license_id, m.license_ref_id, m.license_type));
    }

    // assert(ctx, result).await?;

    // ingest second time

    // let result = ctx
    //     .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
    //     .await?;
    // assert(ctx, result).await?;

    // done

    Ok(())
}
