use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .rename_table(
                Table::rename()
                    .table(Package::Table, BasePurl::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(PackageVersion::Table, VersionedPurl::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(QualifiedPackage::Table, QualifiedPurl::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .rename_table(
                Table::rename()
                    .table(QualifiedPurl::Table, QualifiedPackage::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(VersionedPurl::Table, PackageVersion::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(BasePurl::Table, Package::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Package {
    Table,
}

#[derive(DeriveIden)]
enum PackageVersion {
    Table,
}

#[derive(DeriveIden)]
enum QualifiedPackage {
    Table,
}

#[derive(DeriveIden)]
enum BasePurl {
    Table,
}

#[derive(DeriveIden)]
enum VersionedPurl {
    Table,
}

#[derive(DeriveIden)]
enum QualifiedPurl {
    Table,
}
