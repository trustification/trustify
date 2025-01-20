use sea_orm_migration::prelude::extension::postgres::Type;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_type(
                Type::create()
                    .as_enum(LicenseCategory::LicenseCategory)
                    .values([
                        LicenseCategory::SLC,
                        LicenseCategory::CLCI,
                        LicenseCategory::CLCN,
                        LicenseCategory::CLE,
                        LicenseCategory::SLD,
                        LicenseCategory::CD,
                        LicenseCategory::O,
                    ])
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_type(
                Type::drop()
                    .name(LicenseCategory::LicenseCategory)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
// #[sea_orm(string_value = "slc")]
// SPDXDECLARED,
// #[sea_orm(string_value = "sld")]
// SPDXCONCLUDED,
// #[sea_orm(string_value = "clci")]
// CYDXLCID,
// #[sea_orm(string_value = "clcn")]
// CYDXLCNAME,
// #[sea_orm(string_value = "cle")]
// CYDXLEXPRESSION,
// #[sea_orm(string_value = "cd")]
// CLEARLYDEFINED,
// #[sea_orm(string_value = "o")]
#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum LicenseCategory {
    LicenseCategory,
    SLC,
    SLD,
    CLCI,
    CLCN,
    CLE,
    CD,
    O,
}
