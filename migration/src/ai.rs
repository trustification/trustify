pub use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migration_table_name() -> DynIden {
        #[derive(DeriveIden)]
        enum AiTables {
            AiMigrations,
        }

        AiTables::AiMigrations.into_iden()
    }

    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(crate::m0000820_create_conversation::Migration)]
    }
}
