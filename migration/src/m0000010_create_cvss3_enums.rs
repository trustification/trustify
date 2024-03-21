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
                    .as_enum(Cvss3Av::Cvss3Av)
                    .values([Cvss3Av::N, Cvss3Av::A, Cvss3Av::L, Cvss3Av::P])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss3Ac::Cvss3Ac)
                    .values([Cvss3Ac::L, Cvss3Ac::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss3Pr::Cvss3Pr)
                    .values([Cvss3Pr::N, Cvss3Pr::L, Cvss3Pr::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss3Ui::Cvss3Ui)
                    .values([Cvss3Ui::N, Cvss3Ui::R])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss3S::Cvss3S)
                    .values([Cvss3S::U, Cvss3S::C])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss3C::Cvss3C)
                    .values([Cvss3C::N, Cvss3C::L, Cvss3C::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss3I::Cvss3I)
                    .values([Cvss3I::N, Cvss3I::L, Cvss3I::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss3A::Cvss3A)
                    .values([Cvss3A::N, Cvss3A::L, Cvss3A::H])
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_type(Type::drop().name(Cvss3A::Cvss3A).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss3I::Cvss3I).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss3C::Cvss3C).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss3S::Cvss3S).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss3Ui::Cvss3Ui).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss3Pr::Cvss3Pr).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss3Ac::Cvss3Ac).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss3Av::Cvss3Av).to_owned())
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss3Av {
    Cvss3Av,
    N,
    A,
    L,
    P,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss3Ac {
    Cvss3Ac,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss3Pr {
    Cvss3Pr,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss3Ui {
    Cvss3Ui,
    N,
    R,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss3S {
    Cvss3S,
    U,
    C,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss3C {
    Cvss3C,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss3I {
    Cvss3I,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss3A {
    Cvss3A,
    N,
    L,
    H,
}
