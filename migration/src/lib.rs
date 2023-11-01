pub use sea_orm_migration::prelude::*;

pub mod m000001_create_package_type;
pub mod m000002_create_package_namespace;
pub mod m000003_create_package_name;
pub mod m000005_create_package;
pub mod m000006_create_package_qualifier;
mod m000007_create_package_dependency;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m000001_create_package_type::Migration),
            Box::new(m000002_create_package_namespace::Migration),
            Box::new(m000003_create_package_name::Migration),
            Box::new(m000005_create_package::Migration),
            Box::new(m000006_create_package_qualifier::Migration),
            Box::new(m000007_create_package_dependency::Migration),
        ]
    }
}

pub struct Now;

impl Iden for Now {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "now").unwrap()
    }
}
