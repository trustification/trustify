use crate::UuidV4;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Cpe::Table)
                    .modify_column(ColumnDef::new(Cpe::Id).uuid().not_null())
                    .to_owned(),
            )
            .await?;

        // TODO: consider converting existing CPEs to have a v5 UUID, based on the existing data.
        // That would also mean updating all referenced keys. There's no need to migrate back
        // however.

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Cpe::Table)
                    .modify_column(
                        ColumnDef::new(Cpe::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4)),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Cpe {
    Table,
    Id,
}
