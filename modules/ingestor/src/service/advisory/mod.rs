use crate::service::Error;
use std::str::FromStr;

pub mod csaf;
pub mod osv;

pub enum Format {
    OSV,
    CSAF,
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "osv" => Ok(Self::OSV),
            "csaf" => Ok(Self::CSAF),
            _ => Err(Error::Generic(anyhow::Error::msg(
                "Unsupported advisory format",
            ))),
        }
    }
}
