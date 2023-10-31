use sea_orm_migration::prelude::*;

use crate::m20220101_000001_create_package_type::PackageType;
use crate::m20220101_000002_create_package_namespace::PackageNamespace;
use crate::m20220101_000003_create_package_name::PackageName;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(Package::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Package::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key()
                    )
                    .col(
                        ColumnDef::new(Package::PackageTypeId)
                            .integer()
                            .not_null()
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("package_type_id")
                            .from(Package::Table, Package::PackageTypeId)
                            .to(PackageType::Table, PackageType::Id)
                    )
                    .col(
                        ColumnDef::new(Package::PackageNamespaceId)
                            .integer()
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("package_namespace_id")
                            .from(Package::Table, Package::PackageNamespaceId)
                            .to(PackageNamespace::Table, PackageNamespace::Id)
                    )
                    .col(
                        ColumnDef::new(Package::PackageNameId)
                            .integer()
                            .not_null()
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("package_name_id")
                            .from(Package::Table, Package::PackageNameId)
                            .to(PackageName::Table, PackageName::Id)
                    )
                    .col(
                        ColumnDef::new(Package::Version)
                            .string()
                            .not_null()
                    )
                    .col(
                        ColumnDef::new(Package::Subpath)
                            .string()
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Package::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Package {
    Table,
    Id,
    PackageTypeId,
    PackageNamespaceId,
    PackageNameId,
    Version,
    Subpath,
}
