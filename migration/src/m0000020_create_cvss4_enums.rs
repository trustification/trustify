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
                    .as_enum(Cvss4Av::Cvss4Av)
                    .values([Cvss4Av::N, Cvss4Av::A, Cvss4Av::L, Cvss4Av::P])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Ac::Cvss4Ac)
                    .values([Cvss4Ac::L, Cvss4Ac::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4At::Cvss4At)
                    .values([Cvss4At::N, Cvss4At::P])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Pr::Cvss4Pr)
                    .values([Cvss4Pr::N, Cvss4Pr::L, Cvss4Pr::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Ui::Cvss4Ui)
                    .values([Cvss4Ui::N, Cvss4Ui::P, Cvss4Ui::A])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Vc::Cvss4Vc)
                    .values([Cvss4Vc::N, Cvss4Vc::L, Cvss4Vc::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Vi::Cvss4Vi)
                    .values([Cvss4Vi::N, Cvss4Vi::L, Cvss4Vi::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Va::Cvss4Va)
                    .values([Cvss4Va::N, Cvss4Va::L, Cvss4Va::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Sc::Cvss4Sc)
                    .values([Cvss4Sc::N, Cvss4Sc::L, Cvss4Sc::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Si::Cvss4Si)
                    .values([Cvss4Si::N, Cvss4Si::L, Cvss4Si::H])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(Cvss4Sa::Cvss4Sa)
                    .values([Cvss4Sa::N, Cvss4Sa::L, Cvss4Sa::H])
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_type(Type::drop().name(Cvss4Sa::Cvss4Sa).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4Si::Cvss4Si).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4Sc::Cvss4Sc).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4Va::Cvss4Va).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4Vi::Cvss4Vi).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4Vc::Cvss4Vc).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4Ui::Cvss4Ui).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4Pr::Cvss4Pr).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4At::Cvss4At).to_owned())
            .await?;
        manager
            .drop_type(Type::drop().name(Cvss4Ac::Cvss4Ac).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Cvss4Av::Cvss4Av).to_owned())
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Av {
    Cvss4Av,
    N,
    A,
    L,
    P,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Ac {
    Cvss4Ac,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4At {
    Cvss4At,
    N,
    P,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Pr {
    Cvss4Pr,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Ui {
    Cvss4Ui,
    N,
    P,
    A,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Vc {
    Cvss4Vc,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Vi {
    Cvss4Vi,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Va {
    Cvss4Va,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Sc {
    Cvss4Sc,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Si {
    Cvss4Si,
    N,
    L,
    H,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Cvss4Sa {
    Cvss4Sa,
    N,
    L,
    H,
}
