pub use sea_orm_migration::prelude::*;

mod m000001_sbom;
mod m000004_create_package;
mod m000016_create_package_dependency;
mod m000005_create_package_qualifier;
mod m000006_create_cve;
mod m000011_package_scan_vulnerability;
mod m000010_vulnerability_fixed;
mod m000018_sbom_describes_cpe;
mod m000019_sbom_describes_package;
mod m000012_create_sbom_dependency;
mod m000003_advisory;
mod m000002_advisory_source;
mod m000007_create_cwe;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m000001_sbom::Migration),
            Box::new(m000002_advisory_source::Migration),
            Box::new(m000003_advisory::Migration),
            Box::new(m000004_create_package::Migration),
            Box::new(m000005_create_package_qualifier::Migration),
            Box::new(m000006_create_cve::Migration),
            Box::new(m000010_vulnerability_fixed::Migration),
            Box::new(m000011_package_scan_vulnerability::Migration),
            Box::new(m000012_create_sbom_dependency::Migration),
            Box::new(m000016_create_package_dependency::Migration),
            Box::new(m000018_sbom_describes_cpe::Migration),
            Box::new(m000019_sbom_describes_package::Migration),
        ]
    }
}

pub struct Now;

impl Iden for Now {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}
