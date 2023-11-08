use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(AdvisorySource::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AdvisorySource::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AdvisorySource::Name).string())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AdvisorySource::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum AdvisorySource {
    Table,
    Id,
    Name,
}
