use serde::Serialize;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Serialize)]
#[non_exhaustive]
pub enum HashKey {
    Sha256(String),
    Sha384(String),
    Sha512(String),
}

impl Display for HashKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HashKey::Sha256(inner) => {
                write!(f, "sha256:{}", inner)
            }
            HashKey::Sha384(inner) => {
                write!(f, "sha385:{}", inner)
            }
            HashKey::Sha512(inner) => {
                write!(f, "sha512:{}", inner)
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HashKeyError {
    #[error("Missing prefix")]
    MissingPrefix,
    #[error("Unsupported algorithm {0}")]
    UnsupportedAlgorithm(String),
}

impl FromStr for HashKey {
    type Err = HashKeyError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        if let Some((prefix, value)) = key.split_once(':') {
            match prefix {
                "sha256" => Ok(Self::Sha256(value.to_string())),
                "sha384" => Ok(Self::Sha384(value.to_string())),
                "sha512" => Ok(Self::Sha512(value.to_string())),
                _ => Err(Self::Err::UnsupportedAlgorithm(prefix.to_string())),
            }
        } else {
            Err(Self::Err::MissingPrefix)
        }
    }
}
