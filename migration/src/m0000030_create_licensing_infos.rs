use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(LicensingInfos::Table)
                    .col(
                        ColumnDef::new(LicensingInfos::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(LicensingInfos::Name).string().not_null())
                    .col(
                        ColumnDef::new(LicensingInfos::LicenseId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(LicensingInfos::SbomId).uuid().not_null())
                    .col(ColumnDef::new(LicensingInfos::ExtractedText).string())
                    .col(ColumnDef::new(LicensingInfos::Comment).string())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(LicensingInfos::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LicensingInfos::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum LicensingInfos {
    Table,
    Id,
    SbomId,
    Name,
    LicenseId,
    ExtractedText,
    Comment,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    SbomId,
}
