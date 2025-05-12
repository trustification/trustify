use sea_orm::{DeriveActiveEnum, EnumIter};
use std::fmt;

#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    strum::VariantArray,
    strum::EnumString,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "signature_type")]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
// When adding a new variant, also add this to the "signature_type" enum.
pub enum SignatureType {
    #[sea_orm(string_value = "pgp")]
    Pgp,
}

impl fmt::Display for SignatureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(SignatureType::Pgp.to_string(), "pgp");
    }
}
