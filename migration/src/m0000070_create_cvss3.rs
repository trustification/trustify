use crate::m0000010_create_cvss3_enums::{
    Cvss3A, Cvss3Ac, Cvss3Av, Cvss3C, Cvss3I, Cvss3Pr, Cvss3S, Cvss3Ui,
};
use crate::m0000060_create_advisory::Advisory;
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
                    .table(Cvss3::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Cvss3::AdvisoryId).integer().not_null())
                    .col(ColumnDef::new(Cvss3::VulnerabilityId).integer().not_null())
                    .col(ColumnDef::new(Cvss3::MinorVersion).integer().not_null())
                    .primary_key(
                        Index::create()
                            .col(Cvss3::VulnerabilityId)
                            .col(Cvss3::AdvisoryId)
                            .col(Cvss3::MinorVersion),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(Cvss3::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(Cvss3::VulnerabilityId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(Cvss3::AV)
                            .enumeration(
                                Cvss3Av::Cvss3Av,
                                [Cvss3Av::N, Cvss3Av::A, Cvss3Av::L, Cvss3Av::P],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::AC)
                            .enumeration(Cvss3Ac::Cvss3Ac, [Cvss3Ac::L, Cvss3Ac::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::PR)
                            .enumeration(Cvss3Pr::Cvss3Pr, [Cvss3Pr::N, Cvss3Pr::L, Cvss3Pr::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::UI)
                            .enumeration(Cvss3Ui::Cvss3Ui, [Cvss3Ui::N, Cvss3Ui::R])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::S)
                            .enumeration(Cvss3S::Cvss3S, [Cvss3S::U, Cvss3S::C])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::C)
                            .enumeration(Cvss3C::Cvss3C, [Cvss3C::N, Cvss3C::L, Cvss3C::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::I)
                            .enumeration(Cvss3I::Cvss3I, [Cvss3I::N, Cvss3I::L, Cvss3I::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss3::A)
                            .enumeration(Cvss3A::Cvss3A, [Cvss3A::N, Cvss3A::L, Cvss3A::H])
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Cvss3::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Cvss3 {
    Table,
    AdvisoryId,
    VulnerabilityId,
    MinorVersion,
    AV,
    AC,
    PR,
    UI,
    S,
    C,
    I,
    A,
}
