use crate::m0000020_create_cvss4_enums::{
    Cvss4Ac, Cvss4At, Cvss4Av, Cvss4Pr, Cvss4Sa, Cvss4Sc, Cvss4Si, Cvss4Ui, Cvss4Va, Cvss4Vc,
    Cvss4Vi,
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
                    .table(Cvss4::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Cvss4::AdvisoryId).uuid().not_null())
                    .col(ColumnDef::new(Cvss4::VulnerabilityId).uuid().not_null())
                    .col(ColumnDef::new(Cvss4::MinorVersion).integer().not_null())
                    .primary_key(
                        Index::create()
                            .col(Cvss4::VulnerabilityId)
                            .col(Cvss4::AdvisoryId)
                            .col(Cvss4::MinorVersion),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(Cvss4::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(Cvss4::VulnerabilityId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(Cvss4::AV)
                            .enumeration(
                                Cvss4Av::Cvss4Av,
                                [Cvss4Av::N, Cvss4Av::A, Cvss4Av::L, Cvss4Av::P],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::AC)
                            .enumeration(Cvss4Ac::Cvss4Ac, [Cvss4Ac::L, Cvss4Ac::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::AT)
                            .enumeration(Cvss4At::Cvss4At, [Cvss4At::N, Cvss4At::P])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::PR)
                            .enumeration(Cvss4Pr::Cvss4Pr, [Cvss4Pr::N, Cvss4Pr::L, Cvss4Pr::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::UI)
                            .enumeration(Cvss4Ui::Cvss4Ui, [Cvss4Ui::N, Cvss4Ui::P, Cvss4Ui::A])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::VC)
                            .enumeration(Cvss4Vc::Cvss4Vc, [Cvss4Vc::N, Cvss4Vc::L, Cvss4Vc::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::VI)
                            .enumeration(Cvss4Vi::Cvss4Vi, [Cvss4Vi::N, Cvss4Vi::L, Cvss4Vi::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::VA)
                            .enumeration(Cvss4Va::Cvss4Va, [Cvss4Va::N, Cvss4Va::L, Cvss4Va::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::SC)
                            .enumeration(Cvss4Sc::Cvss4Sc, [Cvss4Sc::N, Cvss4Sc::L, Cvss4Sc::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::SI)
                            .enumeration(Cvss4Si::Cvss4Si, [Cvss4Si::N, Cvss4Si::L, Cvss4Si::H])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Cvss4::SA)
                            .enumeration(Cvss4Sa::Cvss4Sa, [Cvss4Sa::N, Cvss4Sa::L, Cvss4Sa::H])
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Cvss4::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Cvss4 {
    Table,
    AdvisoryId,
    VulnerabilityId,
    MinorVersion,
    AV,
    AC,
    AT,
    PR,
    UI,
    VC,
    VI,
    VA,
    SC,
    SI,
    SA,
}
