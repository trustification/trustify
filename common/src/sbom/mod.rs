use crate::cpe22::Cpe22;
use crate::purl::Purl;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum SbomLocator {
    Id(i32),
    Location(String),
    Sha256(String),
    Purl(Purl),
    Cpe22(Cpe22),
}

pub enum Describes {
    Purl(Purl),
    Cpe22(String),
}
