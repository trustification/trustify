pub use sea_orm_migration::prelude::*;

mod m000001_create_package;
mod m000002_create_package_qualifier;
mod m000003_create_package_dependency;
mod m000004_create_vulnerability;
mod m000005_package_vulnerability;
mod m000006_vulnerability_fixed;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m000001_create_package::Migration),
            Box::new(m000002_create_package_qualifier::Migration),
            Box::new(m000003_create_package_dependency::Migration),
            Box::new(m000004_create_vulnerability::Migration),
            Box::new(m000005_package_vulnerability::Migration),
            Box::new(m000006_vulnerability_fixed::Migration),
        ]
    }
}

pub struct Now;

impl Iden for Now {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}
