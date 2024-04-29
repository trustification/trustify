use crate::m0000120_create_package_version::PackageVersion;
use sea_orm_migration::prelude::*;

use crate::Now;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(QualifiedPackage::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(QualifiedPackage::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(QualifiedPackage::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(
                        ColumnDef::new(QualifiedPackage::PackageVersionId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(QualifiedPackage::Qualifiers)
                            .json_binary()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(QualifiedPackage::PackageVersionId)
                            .to(PackageVersion::Table, PackageVersion::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(QualifiedPackage::Table)
                    .name(INDEX_BY_PVID)
                    .if_not_exists()
                    .col(QualifiedPackage::PackageVersionId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(QualifiedPackage::Table)
                    .name(INDEX_BY_PVID)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(QualifiedPackage::Table).to_owned())
            .await?;

        Ok(())
    }
}

const INDEX_BY_PVID: &str = "by_pvid";

#[derive(DeriveIden)]
pub enum QualifiedPackage {
    Table,
    Id,
    Timestamp,
    // --
    PackageVersionId,
    Qualifiers,
}
