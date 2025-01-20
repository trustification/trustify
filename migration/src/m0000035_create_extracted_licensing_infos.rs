use sea_orm_migration::prelude::*;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ExtractedLicensingInfos::Table)
                    .col(
                        ColumnDef::new(ExtractedLicensingInfos::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ExtractedLicensingInfos::LicenseId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ExtractedLicensingInfos::SbomId)
                            .uuid()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ExtractedLicensingInfos::ExtractedText).string())
                    .col(ColumnDef::new(ExtractedLicensingInfos::Comment).string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ExtractedLicensingInfos::Table)
                    .to_owned(),
            )
            .await
    }
}

// pub id: Uuid,
// pub sbom_id: Uuid,
// pub licenseId: String,
// // pub name: String,
// pub extracted_text: String,
// pub comment: String,
#[derive(DeriveIden)]
pub enum ExtractedLicensingInfos {
    Table,
    Id,
    SbomId,
    LicenseId,
    ExtractedText,
    Comment,
}
