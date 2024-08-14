pub use sea_orm_migration::prelude::*;

mod m0000010_create_cvss3_enums;
mod m0000020_create_cvss4_enums;
mod m0000022_create_organization;
mod m0000030_create_sbom;
mod m0000040_create_vulnerability;
mod m0000050_create_vulnerability_description;
mod m0000060_create_advisory;
mod m0000070_create_cvss3;
mod m0000080_create_cvss4;
pub mod m0000090_create_advisory_vulnerability;
mod m0000100_create_package;
mod m0000110_create_cpe;
mod m0000120_create_package_version;
mod m0000130_create_qualified_package;
mod m0000140_create_package_version_range;
mod m0000150_create_affected_package_version_range;
mod m0000160_create_fixed_package_version;
mod m0000170_create_not_affected_package_version;
mod m0000210_create_relationship;
mod m0000220_create_package_relates_to_package;
mod m0000230_create_qualified_package_transitive_function;
mod m0000240_create_importer;
mod m0000250_create_sbom_package;
mod m0000260_sbom_package_cpe_ref;
mod m0000270_sbom_package_purl_ref;
mod m0000280_add_advisory_vulnerability_meta;
mod m0000290_create_product;
mod m0000300_create_product_version;
mod m0000301_alter_product_version_index;
mod m0000310_alter_advisory_primary_key;
mod m0000315_create_cvss3_scoring_function;
mod m0000320_create_cvss3_score_column;
mod m0000325_create_cvss3_severity_column;
mod m0000330_add_sbom_version;
mod m0000331_create_status;
mod m0000335_create_version_scheme;
mod m0000337_create_version_range;
mod m0000340_create_package_status;
mod m0000345_create_version_comparison_fns;
mod m0000350_remove_old_assertion_tables;
mod m0000355_labels;
mod m0000360_add_sbom_file;
mod m0000370_add_cwe;
mod m0000380_create_package_status_index;
mod m0000390_rename_package_purl;
mod m0000395_alter_vulnerability_pk;
mod m0000410_labels_index;
mod m0000420_add_digests;
mod m0000440_alter_package_status_to_purl_status;
mod m0000445_create_purl_status_cpe;
mod m0000450_alter_cpe_uuidv5;
mod m0000460_add_vulnerability_description_adv;
mod m0000470_cascade_sbom_delete;
mod m0000475_improve_version_comparison_fns;
mod m0000480_create_rpmver_cmp_fns;
mod m0000485_create_gitver_cmp_fns;
mod m0000490_cascade_advisory_delete;
mod m0000500_fix_sbom_node_fks;
mod m0000501_perf_indexes;
mod m0000510_create_maven_cmp_fns;
mod m0000520_scale_indexes;
mod m0000530_base_purl_index;
mod m0000540_ingestion_indexes;
mod m0000543_create_license;
mod m0000545_create_purl_license_assertion;
mod m0000550_create_cpe_license_assertion;
mod m0000560_alter_vulnerability_cwe_column;
mod m0000565_alter_advisory_vulnerability_cwe_column;
mod m0000570_add_import_progress;
mod m0000575_create_weakness;
mod m0000580_mark_fns;
mod m0000590_get_purl_fns;
mod m0000595_analysis_api_index;
mod m0000600_remove_raise_notice_fns;
mod m0000605_create_source_document;
mod m0000610_improve_version_cmp_fns;
mod m0000620_parallel_unsafe_pg_fns;
mod m0000625_alter_qualified_purl_purl_column;
mod m0000630_create_product_version_range;
mod m0000631_alter_product_cpe_key;
mod m0000640_create_product_status;
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0000010_create_cvss3_enums::Migration),
            Box::new(m0000020_create_cvss4_enums::Migration),
            Box::new(m0000022_create_organization::Migration),
            Box::new(m0000030_create_sbom::Migration),
            Box::new(m0000040_create_vulnerability::Migration),
            Box::new(m0000050_create_vulnerability_description::Migration),
            Box::new(m0000060_create_advisory::Migration),
            Box::new(m0000070_create_cvss3::Migration),
            Box::new(m0000080_create_cvss4::Migration),
            Box::new(m0000090_create_advisory_vulnerability::Migration),
            Box::new(m0000100_create_package::Migration),
            Box::new(m0000110_create_cpe::Migration),
            Box::new(m0000120_create_package_version::Migration),
            Box::new(m0000130_create_qualified_package::Migration),
            Box::new(m0000140_create_package_version_range::Migration),
            Box::new(m0000150_create_affected_package_version_range::Migration),
            Box::new(m0000160_create_fixed_package_version::Migration),
            Box::new(m0000170_create_not_affected_package_version::Migration),
            Box::new(m0000210_create_relationship::Migration),
            Box::new(m0000220_create_package_relates_to_package::Migration),
            Box::new(m0000230_create_qualified_package_transitive_function::Migration),
            Box::new(m0000240_create_importer::Migration),
            Box::new(m0000250_create_sbom_package::Migration),
            Box::new(m0000260_sbom_package_cpe_ref::Migration),
            Box::new(m0000270_sbom_package_purl_ref::Migration),
            Box::new(m0000280_add_advisory_vulnerability_meta::Migration),
            Box::new(m0000290_create_product::Migration),
            Box::new(m0000300_create_product_version::Migration),
            Box::new(m0000301_alter_product_version_index::Migration),
            Box::new(m0000310_alter_advisory_primary_key::Migration),
            Box::new(m0000315_create_cvss3_scoring_function::Migration),
            Box::new(m0000320_create_cvss3_score_column::Migration),
            Box::new(m0000325_create_cvss3_severity_column::Migration),
            Box::new(m0000330_add_sbom_version::Migration),
            Box::new(m0000331_create_status::Migration),
            Box::new(m0000335_create_version_scheme::Migration),
            Box::new(m0000337_create_version_range::Migration),
            Box::new(m0000340_create_package_status::Migration),
            Box::new(m0000345_create_version_comparison_fns::Migration),
            Box::new(m0000350_remove_old_assertion_tables::Migration),
            Box::new(m0000355_labels::Migration),
            Box::new(m0000360_add_sbom_file::Migration),
            Box::new(m0000370_add_cwe::Migration),
            Box::new(m0000380_create_package_status_index::Migration),
            Box::new(m0000390_rename_package_purl::Migration),
            Box::new(m0000395_alter_vulnerability_pk::Migration),
            Box::new(m0000410_labels_index::Migration),
            Box::new(m0000420_add_digests::Migration),
            Box::new(m0000440_alter_package_status_to_purl_status::Migration),
            Box::new(m0000445_create_purl_status_cpe::Migration),
            Box::new(m0000450_alter_cpe_uuidv5::Migration),
            Box::new(m0000460_add_vulnerability_description_adv::Migration),
            Box::new(m0000470_cascade_sbom_delete::Migration),
            Box::new(m0000475_improve_version_comparison_fns::Migration),
            Box::new(m0000480_create_rpmver_cmp_fns::Migration),
            Box::new(m0000485_create_gitver_cmp_fns::Migration),
            Box::new(m0000490_cascade_advisory_delete::Migration),
            Box::new(m0000500_fix_sbom_node_fks::Migration),
            Box::new(m0000501_perf_indexes::Migration),
            Box::new(m0000510_create_maven_cmp_fns::Migration),
            Box::new(m0000520_scale_indexes::Migration),
            Box::new(m0000530_base_purl_index::Migration),
            Box::new(m0000540_ingestion_indexes::Migration),
            Box::new(m0000543_create_license::Migration),
            Box::new(m0000545_create_purl_license_assertion::Migration),
            Box::new(m0000550_create_cpe_license_assertion::Migration),
            Box::new(m0000560_alter_vulnerability_cwe_column::Migration),
            Box::new(m0000565_alter_advisory_vulnerability_cwe_column::Migration),
            Box::new(m0000570_add_import_progress::Migration),
            Box::new(m0000575_create_weakness::Migration),
            Box::new(m0000580_mark_fns::Migration),
            Box::new(m0000590_get_purl_fns::Migration),
            Box::new(m0000595_analysis_api_index::Migration),
            Box::new(m0000600_remove_raise_notice_fns::Migration),
            Box::new(m0000605_create_source_document::Migration),
            Box::new(m0000610_improve_version_cmp_fns::Migration),
            Box::new(m0000620_parallel_unsafe_pg_fns::Migration),
            Box::new(m0000625_alter_qualified_purl_purl_column::Migration),
            Box::new(m0000630_create_product_version_range::Migration),
            Box::new(m0000631_alter_product_cpe_key::Migration),
            Box::new(m0000640_create_product_status::Migration),
        ]
    }
}

pub struct Now;

impl Iden for Now {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}

pub struct UuidV4;

impl Iden for UuidV4 {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "gen_random_uuid").unwrap()
    }
}
