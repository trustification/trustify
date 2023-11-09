use crate::m0000040_create_package::Package;
use crate::m0000044_create_qualified_package::QualifiedPackage;
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
                        ColumnDef::new(PackageQualifier::QualifiedPackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("package_id")
                            .from(
                                PackageQualifier::Table,
                                PackageQualifier::QualifiedPackageId,
                            )
                            .to(QualifiedPackage::Table, QualifiedPackage::Id),
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
    QualifiedPackageId,
    Key,
    Value,
}
