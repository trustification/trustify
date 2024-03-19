use crate::cvss3::{Cvss3Base, Cvss3Error};
use crate::cvss4::{Cvss4Base, Cvss4Error};
use std::str::FromStr;

pub mod cvss3;
pub mod cvss4;

#[derive(Debug, Copy, Clone)]
pub enum CvssBase {
    Cvss3(Cvss3Base),
    Cvss4(Cvss4Base),
}

#[derive(Debug, Copy, Clone)]
pub enum CvssError {
    MajorVersion,
    Cvss3(Cvss3Error),
    Cvss4(Cvss4Error),
}

impl From<Cvss3Error> for CvssError {
    fn from(value: Cvss3Error) -> Self {
        Self::Cvss3(value)
    }
}

impl From<Cvss4Error> for CvssError {
    fn from(value: Cvss4Error) -> Self {
        Self::Cvss4(value)
    }
}

impl FromStr for CvssBase {
    type Err = CvssError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("CVSS:3") {
            Ok(CvssBase::Cvss3(Cvss3Base::from_str(s)?))
        } else if s.starts_with("CVSS:4") {
            Ok(CvssBase::Cvss4(Cvss4Base::from_str(s)?))
        } else {
            Err(Self::Err::MajorVersion)
        }
    }
}
