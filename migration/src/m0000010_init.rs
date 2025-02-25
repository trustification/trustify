use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// This migration squashes MANY previous migrations.  If you need to write a new one,
// and you would like to see some examples of how they were written, you can browse those previous migrations at:
// https://github.com/trustification/trustify/tree/2f72e0efd3f84e69c068b087b86f909135e64eee/migration/src
#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // the data for this migration extracted using:
        //     pg_dump --no-owner --clean --no-privileges --inserts -U postgres trustify > migration/src/m0000010_init_up.sql
        // Delete the SET statements at the start of the file
        // Move the drop statements at the start to m0000010_init_down.sql

        let x = manager
            .get_connection()
            .execute_unprepared(include_str!("m0000010_init_up.sql"))
            .await
            .map(|_| ());
        x?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000010_init_down.sql"))
            .await
            .map(|_| ())?;
        Ok(())
    }
}
