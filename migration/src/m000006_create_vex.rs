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
                    .table(Cve::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Cve::Id).string().not_null().primary_key())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CveAffected::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(CveAffected::Id).string().not_null())
                    .col(ColumnDef::new(CveAffected::Purl).string().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(CveAffected::Id)
                            .to(Cve::Table, Cve::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .primary_key(Index::create().col(CveAffected::Id).col(CveAffected::Purl))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Cve::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(CveAffected::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Cve {
    Table,
    Id,
    // --
}

#[derive(DeriveIden)]
pub enum CveAffected {
    Table,
    Id,
    Purl,
    // --
}
