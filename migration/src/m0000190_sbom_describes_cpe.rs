use crate::m0000030_create_sbom::Sbom;
use crate::m0000110_create_cpe::Cpe;
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
                    .col(
                        ColumnDef::new(SbomDescribesCpe::SbomId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(SbomDescribesCpe::Table, SbomDescribesCpe::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(ColumnDef::new(SbomDescribesCpe::CpeId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("cpe22_id")
                            .from(SbomDescribesCpe::Table, SbomDescribesCpe::CpeId)
                            .to(Cpe::Table, Cpe::Id),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-sbom-cpe")
                            .col(SbomDescribesCpe::SbomId)
                            .col(SbomDescribesCpe::CpeId)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SbomDescribesCpe::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomDescribesCpe {
    Table,
    SbomId,
    CpeId,
}
