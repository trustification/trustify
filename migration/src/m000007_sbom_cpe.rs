use crate::m000001_sbom::Sbom;
use crate::m000002_create_package::Package;
use crate::m000004_create_vulnerability::Vulnerability;
use crate::m000007_sbom_cpe::SbomCpe::SbomId;
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
                    .table(SbomCpe::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SbomCpe::SbomId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(SbomCpe::Table, SbomCpe::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(ColumnDef::new(SbomCpe::Cpe).integer().not_null())
                    .primary_key(
                        Index::create()
                            .name("pk-sbom-cpe")
                            .col(SbomCpe::SbomId)
                            .col(SbomCpe::Cpe)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SbomCpe::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomCpe {
    Table,
    SbomId,
    Cpe,
}
