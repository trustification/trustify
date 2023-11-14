use crate::purl::Purl;

#[derive(Debug, Clone)]
pub enum SbomLocator {
    Id(i32),
    Location(String),
    Sha256(String),
    Purl(Purl),
    Cpe(String),
}


pub enum Describes {
    Purl(Purl),
    Cpe(String),
}