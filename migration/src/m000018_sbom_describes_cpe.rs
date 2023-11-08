use crate::m000001_sbom::Sbom;
use crate::m000004_create_package::Package;
use crate::m000006_create_cve::Cve;
use crate::m000018_sbom_describes_cpe::SbomDescribesCpe::SbomId;
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
                    .table(SbomDescribesCpe::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SbomDescribesCpe::SbomId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(SbomDescribesCpe::Table, SbomDescribesCpe::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(ColumnDef::new(SbomDescribesCpe::Cpe).string().not_null())
                    .primary_key(
                        Index::create()
                            .name("pk-sbom-cpe")
                            .col(SbomDescribesCpe::SbomId)
                            .col(SbomDescribesCpe::Cpe)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SbomDescribesCpe::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomDescribesCpe {
    Table,
    SbomId,
    Cpe,
}
