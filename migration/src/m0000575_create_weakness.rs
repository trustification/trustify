use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Weakness::Table)
                    .col(ColumnDef::new(Weakness::Id).text().not_null().primary_key())
                    .col(ColumnDef::new(Weakness::Description).text().not_null())
                    .col(ColumnDef::new(Weakness::ExtendedDescription).text())
                    .col(ColumnDef::new(Weakness::ChildOf).array(ColumnType::Text))
                    .col(ColumnDef::new(Weakness::ParentOf).array(ColumnType::Text))
                    .col(ColumnDef::new(Weakness::StartsWith).array(ColumnType::Text))
                    .col(ColumnDef::new(Weakness::CanFollow).array(ColumnType::Text))
                    .col(ColumnDef::new(Weakness::CanPrecede).array(ColumnType::Text))
                    .col(ColumnDef::new(Weakness::RequiredBy).array(ColumnType::Text))
                    .col(ColumnDef::new(Weakness::Requires).array(ColumnType::Text))
                    .col(ColumnDef::new(Weakness::CanAlsoBe).array(ColumnType::Text))
                    .col(ColumnDef::new(Weakness::PeerOf).array(ColumnType::Text))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Weakness::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Weakness {
    Table,
    Id,
    Description,
    ExtendedDescription,
    ChildOf,
    ParentOf,
    StartsWith,
    CanFollow,
    CanPrecede,
    RequiredBy,
    Requires,
    CanAlsoBe,
    PeerOf,
}
