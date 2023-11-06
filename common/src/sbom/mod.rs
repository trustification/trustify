use crate::purl::Purl;

pub enum SbomIdentifier {
    Purl(Purl),
    Cpe(String)
}