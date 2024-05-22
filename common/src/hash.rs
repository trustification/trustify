use serde::de::{Error, Visitor};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum HashKey {
    Sha256(String),
    Sha384(String),
    Sha512(String),
}

impl Serialize for HashKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HashKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HashKeyVisitor)
    }
}

struct HashKeyVisitor;

impl<'de> Visitor<'de> for HashKeyVisitor {
    type Value = HashKey;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a hash key with a valid prefix")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        HashKey::from_str(v).map_err(|e| E::custom(e.to_string()))
    }
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

#[cfg(test)]
mod test {
    use crate::hash::HashKey;
    use serde_json::json;

    #[test]
    fn deserialize() -> Result<(), anyhow::Error> {
        let raw = "sha256:123123";

        let key: HashKey = serde_json::from_value(json!("sha256:123123"))?;

        assert_eq!(key, HashKey::Sha256("123123".to_string()));

        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), anyhow::Error> {
        let key = HashKey::Sha256("123123".to_string());

        let raw = serde_json::to_string(&key)?;

        assert_eq!(raw, "\"sha256:123123\"");
        Ok(())
    }
}
