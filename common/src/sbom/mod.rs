use crate::cpe::Cpe;
use crate::purl::Purl;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum SbomLocator {
    Id(i32),
    Location(String),
    Sha256(String),
    Purl(Purl),
    Cpe(Cpe),
}

pub enum Describes {
    Purl(Purl),
    Cpe(String),
}
