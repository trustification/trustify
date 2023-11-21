use crate::m0000010_create_sbom::Sbom;
use crate::m0000035_create_cpe22::Cpe22;
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
                    .table(SbomDescribesCpe22::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SbomDescribesCpe22::SbomId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(SbomDescribesCpe22::Table, SbomDescribesCpe22::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(
                        ColumnDef::new(SbomDescribesCpe22::Cpe22Id)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("cpe22_id")
                            .from(SbomDescribesCpe22::Table, SbomDescribesCpe22::Cpe22Id)
                            .to(Cpe22::Table, Cpe22::Id),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-sbom-cpe")
                            .col(SbomDescribesCpe22::SbomId)
                            .col(SbomDescribesCpe22::Cpe22Id)
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
                    .table(SbomDescribesCpe22::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomDescribesCpe22 {
    Table,
    SbomId,
    Cpe22Id,
}
