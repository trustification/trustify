use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::CVSS3AdvisoryIdFkey.to_string())
                    .from(CVSS3::Table, CVSS3::AdvisoryId)
                    .to(Advisory::Table, Advisory::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::CVSS4AdvisoryIdFkey.to_string())
                    .from(CVSS4::Table, CVSS4::AdvisoryId)
                    .to(Advisory::Table, Advisory::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProductVersion::Table)
                    .drop_foreign_key(Keys::ProductVersionSbomIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::ProductVersionSbomIdFkey.to_string())
                    .from(ProductVersion::Table, ProductVersion::SbomId)
                    .to(Sbom::Table, Sbom::SbomId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CVSS3::Table)
                    .drop_foreign_key(Keys::CVSS3AdvisoryIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CVSS4::Table)
                    .drop_foreign_key(Keys::CVSS4AdvisoryIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProductVersion::Table)
                    .drop_foreign_key(Keys::ProductVersionSbomIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::ProductVersionSbomIdFkey.to_string())
                    .from(ProductVersion::Table, ProductVersion::SbomId)
                    .to(Sbom::Table, Sbom::SbomId)
                    .on_delete(ForeignKeyAction::SetNull)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum CVSS3 {
    Table,
    AdvisoryId,
}

#[derive(DeriveIden)]
enum CVSS4 {
    Table,
    AdvisoryId,
}

#[derive(DeriveIden)]
enum Advisory {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ProductVersion {
    Table,
    SbomId,
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    SbomId,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Keys {
    CVSS3AdvisoryIdFkey,
    CVSS4AdvisoryIdFkey,
    ProductVersionSbomIdFkey,
}
