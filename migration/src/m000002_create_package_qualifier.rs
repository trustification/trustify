use crate::m000001_create_package::Package;
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
                    .table(PackageQualifier::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PackageQualifier::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PackageQualifier::PackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("package_id")
                            .from(PackageQualifier::Table, PackageQualifier::PackageId)
                            .to(Package::Table, Package::Id),
                    )
                    .col(ColumnDef::new(PackageQualifier::Key).string().not_null())
                    .col(ColumnDef::new(PackageQualifier::Value).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PackageQualifier::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum PackageQualifier {
    Table,
    Id,
    PackageId,
    Key,
    Value,
}
