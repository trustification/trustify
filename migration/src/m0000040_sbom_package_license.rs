use crate::UuidV4;
use crate::m0000030_create_licensing_infos::LicensingInfos;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SbomPackageLicense::Table)
                    .col(
                        ColumnDef::new(SbomPackageLicense::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4)),
                    )
                    .col(ColumnDef::new(SbomPackageLicense::SbomId).uuid().not_null())
                    .col(
                        ColumnDef::new(SbomPackageLicense::LicenseId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomPackageLicense::NodeId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomPackageLicense::LicenseType)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(LicensingInfos::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(LicensingInfos::LicenseId)
                            .to(License::Table, License::Id),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomPackageLicense::SbomId)
                            .col(SbomPackageLicense::NodeId)
                            .col(SbomPackageLicense::LicenseId)
                            .col(SbomPackageLicense::LicenseType)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SbomPackageLicense::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomPackageLicense {
    Table,
    Id,
    SbomId,
    NodeId,
    LicenseId,
    LicenseType,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    SbomId,
}

#[derive(DeriveIden)]
pub enum License {
    Table,
    Id,
}
