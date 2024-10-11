use sea_orm::entity::prelude::*;

#[derive(Copy, Clone, Eq, Hash, Debug, PartialEq, EnumIter, DeriveActiveEnum, strum::Display)]
#[sea_orm(
    rs_type = "String",
    db_type = "String(StringLen::None)",
    rename_all = "camelCase"
)]
#[strum(serialize_all = "camelCase")]
pub enum VersionScheme {
    Generic,
    Git,
    Semver,
    Rpm,
    Python,
    Maven,
}
