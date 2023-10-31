pub use sea_orm_migration::prelude::*;

pub mod m20220101_000001_create_package_type;
pub mod m20220101_000002_create_package_namespace;
pub mod m20220101_000003_create_package_name;
pub mod m20220101_000006_create_package_qualifier;
pub mod m20220101_000005_create_package;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_package_type::Migration),
            Box::new(m20220101_000002_create_package_namespace::Migration),
            Box::new(m20220101_000003_create_package_name::Migration),
            Box::new(m20220101_000005_create_package::Migration),
            Box::new(m20220101_000006_create_package_qualifier::Migration),
        ]
    }
}
