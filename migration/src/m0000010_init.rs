use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

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
