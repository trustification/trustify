pub use sea_orm_migration::prelude::*;

mod m0000010_create_sbom;
mod m0000011_create_vulnerability;
mod m0000030_create_advisory;
pub mod m0000032_create_advisory_vulnerability;
mod m0000040_create_package;
mod m0000042_create_package_version;
mod m0000044_create_qualified_package;
mod m0000046_create_package_version_range;
mod m0000047_create_affected_package_version_range;
mod m0000048_create_fixed_package_version;
mod m0000049_create_not_affected_package_version;
mod m0000050_create_package_qualifier;
mod m0000070_create_cwe;
mod m0000180_sbom_describes_cpe22;
mod m0000190_sbom_describes_package;
mod m0000200_create_relationship;
mod m0000210_create_package_relates_to_package;

mod m0000012_create_vulnerability_description;
mod m0000035_create_cpe22;
mod m0000220_create_qualified_package_transitive_function;
mod m0000230_create_importer;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0000010_create_sbom::Migration),
            Box::new(m0000011_create_vulnerability::Migration),
            Box::new(m0000012_create_vulnerability_description::Migration),
            Box::new(m0000030_create_advisory::Migration),
            Box::new(m0000032_create_advisory_vulnerability::Migration),
            Box::new(m0000040_create_package::Migration),
            Box::new(m0000035_create_cpe22::Migration),
            Box::new(m0000042_create_package_version::Migration),
            Box::new(m0000044_create_qualified_package::Migration),
            Box::new(m0000046_create_package_version_range::Migration),
            Box::new(m0000047_create_affected_package_version_range::Migration),
            Box::new(m0000048_create_fixed_package_version::Migration),
            Box::new(m0000049_create_not_affected_package_version::Migration),
            Box::new(m0000050_create_package_qualifier::Migration),
            Box::new(m0000180_sbom_describes_cpe22::Migration),
            Box::new(m0000190_sbom_describes_package::Migration),
            Box::new(m0000200_create_relationship::Migration),
            Box::new(m0000210_create_package_relates_to_package::Migration),
            Box::new(m0000220_create_qualified_package_transitive_function::Migration),
            Box::new(m0000230_create_importer::Migration),
        ]
    }
}

pub struct Now;

impl Iden for Now {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}
