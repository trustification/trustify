pub use sea_orm_migration::prelude::*;

mod m0000030_create_sbom;
mod m0000040_create_vulnerability;
mod m0000060_create_advisory;
pub mod m0000090_create_advisory_vulnerability;
mod m0000100_create_package;
mod m0000120_create_package_version;
mod m0000130_create_qualified_package;
mod m0000140_create_package_version_range;
mod m0000150_create_affected_package_version_range;
mod m0000160_create_fixed_package_version;
mod m0000170_create_not_affected_package_version;
mod m0000180_create_package_qualifier;
mod m0000070_create_cwe;
mod m0000190_sbom_describes_cpe;
mod m0000200_sbom_describes_package;
mod m0000210_create_relationship;
mod m0000220_create_package_relates_to_package;

mod m0000010_create_cvss3_enums;
mod m0000020_create_cvss4_enums;
mod m0000050_create_vulnerability_description;
mod m0000070_create_cvss3;
mod m0000080_create_cvss4;
mod m0000110_create_cpe;
mod m0000230_create_qualified_package_transitive_function;
mod m0000240_create_importer;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0000010_create_cvss3_enums::Migration),
            Box::new(m0000020_create_cvss4_enums::Migration),
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
            Box::new(m0000180_create_package_qualifier::Migration),
            Box::new(m0000190_sbom_describes_cpe::Migration),
            Box::new(m0000200_sbom_describes_package::Migration),
            Box::new(m0000210_create_relationship::Migration),
            Box::new(m0000220_create_package_relates_to_package::Migration),
            Box::new(m0000230_create_qualified_package_transitive_function::Migration),
            Box::new(m0000240_create_importer::Migration),
        ]
    }
}

pub struct Now;

impl Iden for Now {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}
