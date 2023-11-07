pub use sea_orm_migration::prelude::*;

mod m000001_sbom;
mod m000004_create_package;
mod m000016_create_package_dependency;
mod m000005_create_package_qualifier;
mod m000006_create_vulnerability;
mod m000011_package_scan_vulnerability;
mod m000010_vulnerability_fixed;
mod m000018_sbom_cpe;
mod m000019_sbom_package;
mod m000012_create_sbom_dependency;
mod m000002_vex;
mod m000003_scanner;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m000001_sbom::Migration),
            Box::new(m000002_vex::Migration),
            Box::new(m000003_scanner::Migration),
            Box::new(m000004_create_package::Migration),
            Box::new(m000005_create_package_qualifier::Migration),
            Box::new(m000006_create_vulnerability::Migration),
            Box::new(m000010_vulnerability_fixed::Migration),
            Box::new(m000011_package_scan_vulnerability::Migration),
            Box::new(m000012_create_sbom_dependency::Migration),
            Box::new(m000016_create_package_dependency::Migration),
            Box::new(m000018_sbom_cpe::Migration),
            Box::new(m000019_sbom_package::Migration),
        ]
    }
}

pub struct Now;

impl Iden for Now {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}
