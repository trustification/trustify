use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Copy,
    Clone,
    Eq,
    Hash,
    Debug,
    PartialEq,
    EnumIter,
    DeriveActiveEnum,
    strum::Display,
    Serialize,
    Deserialize,
)]
#[sea_orm(
    rs_type = "String",
    db_type = "String(StringLen::None)",
    rename_all = "lowercase"
)]
#[strum(serialize_all = "lowercase")]
pub enum VersionScheme {
    Generic,
    Git,
    Semver,
    Rpm,
    Python,
    Maven,
    Golang,
    Npm,
    Packagist,
    NuGet,
    Gem,
    Hex,
}
