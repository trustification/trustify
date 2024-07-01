use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // base purl

        manager
            .rename_table(
                Table::rename()
                    .table(Package::Table, BasePurl::Table)
                    .to_owned(),
            )
            .await?;

        // versioned purl

        manager
            .rename_table(
                Table::rename()
                    .table(PackageVersion::Table, VersionedPurl::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(VersionedPurl::Table)
                    .rename_column(PackageVersion::PackageId, VersionedPurl::BasePurlId)
                    .to_owned(),
            )
            .await?;

        // qualified purl

        manager
            .rename_table(
                Table::rename()
                    .table(QualifiedPackage::Table, QualifiedPurl::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(QualifiedPurl::Table)
                    .rename_column(
                        QualifiedPackage::PackageVersionId,
                        QualifiedPurl::VersionedPurlId,
                    )
                    .to_owned(),
            )
            .await?;

        // sbom package purl ref

        manager
            .alter_table(
                Table::alter()
                    .table(SbomPackagePurlRef::Table)
                    .rename_column(
                        SbomPackagePurlRef::QualifiedPackageId,
                        SbomPackagePurlRef::QualifiedPurlId,
                    )
                    .to_owned(),
            )
            .await?;

        // replace function

        manager
            .get_connection()
            .execute_unprepared(r#"drop function if exists qualified_package_transitive"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000390_qualified_package_transitive_function.sql"
            ))
            .await?;

        // done

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // replace function

        manager
            .get_connection()
            .execute_unprepared(r#"drop function if exists qualified_package_transitive"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function if exists package_transitive"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000230_create_qualified_package_transitive_function.sql"
            ))
            .await?;

        // sbom package purl ref

        manager
            .alter_table(
                Table::alter()
                    .table(SbomPackagePurlRef::Table)
                    .rename_column(
                        SbomPackagePurlRef::QualifiedPurlId,
                        SbomPackagePurlRef::QualifiedPackageId,
                    )
                    .to_owned(),
            )
            .await?;

        // qualified purl

        manager
            .alter_table(
                Table::alter()
                    .table(QualifiedPurl::Table)
                    .rename_column(
                        QualifiedPurl::VersionedPurlId,
                        QualifiedPackage::PackageVersionId,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(QualifiedPurl::Table, QualifiedPackage::Table)
                    .to_owned(),
            )
            .await?;

        // versioned purl

        manager
            .alter_table(
                Table::alter()
                    .table(VersionedPurl::Table)
                    .rename_column(VersionedPurl::BasePurlId, PackageVersion::PackageId)
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

        // base purl

        manager
            .rename_table(
                Table::rename()
                    .table(BasePurl::Table, Package::Table)
                    .to_owned(),
            )
            .await?;

        // done

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
    PackageId,
}

#[derive(DeriveIden)]
enum QualifiedPackage {
    Table,
    PackageVersionId,
}

#[derive(DeriveIden)]
enum BasePurl {
    Table,
}

#[derive(DeriveIden)]
enum VersionedPurl {
    Table,
    BasePurlId,
}

#[derive(DeriveIden)]
enum QualifiedPurl {
    Table,
    VersionedPurlId,
}

#[derive(DeriveIden)]
enum SbomPackagePurlRef {
    Table,

    QualifiedPackageId,
    QualifiedPurlId,
}
