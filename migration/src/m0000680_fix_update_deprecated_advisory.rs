use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // This one is a bit special. The original migration was bugged by a performance issue. So
        // we need to replace that function if it was already present and passed the migration. But
        // We also need to replace the function in case the migration was not yet run. Because
        // otherwise, the migration would not pass.
        //
        // The strategy is to replace the original function with the new content, and re-apply it
        // with this migration. If the original migration did not yet pass, it would now. In any
        // case, this migration ensures the new content of the function from now on.
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000650_alter_advisory_tracking/update_deprecated_advisory.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // As the original version of this function was flawed, we replaced the original content
        // and don't migrate back.
        Ok(())
    }
}
