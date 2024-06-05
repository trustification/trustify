use serde::de::{Error, Visitor};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use utoipa::openapi::{Object, RefOr, Schema, SchemaType};
use utoipa::ToSchema;
use uuid::Uuid;

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum HashOrUuidKey {
    Uuid(Uuid),
    Sha256(String),
    Sha384(String),
    Sha512(String),
}

impl HashOrUuidKey {
    pub fn prefix(&self) -> &'static str {
        match self {
            HashOrUuidKey::Sha256(_) => "sha256",
            HashOrUuidKey::Sha384(_) => "sha384",
            HashOrUuidKey::Sha512(_) => "sha512",
            HashOrUuidKey::Uuid(_) => "urn:uuid",
        }
    }

    pub fn value(&self) -> String {
        match self {
            HashOrUuidKey::Sha256(inner) => inner.clone(),
            HashOrUuidKey::Sha384(inner) => inner.clone(),
            HashOrUuidKey::Sha512(inner) => inner.clone(),
            HashOrUuidKey::Uuid(inner) => inner.simple().to_string(),
        }
    }
}

impl<'__s> ToSchema<'__s> for HashOrUuidKey {
    fn schema() -> (&'__s str, RefOr<Schema>) {
        let mut obj = Object::with_type(SchemaType::String);
        obj.description = Some("A hash/digest prefixed with its type.".to_string());
        obj.example = Some(Value::String(
            "sha256:dc60aeb735c16a71b6fc56e84ddb8193e3a6d1ef0b7e958d77e78fc039a5d04e".to_string(),
        ));

        ("HashKey", RefOr::T(Schema::Object(obj)))
    }
}

impl Serialize for HashOrUuidKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HashOrUuidKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HashKeyVisitor)
    }
}

struct HashKeyVisitor;

impl<'de> Visitor<'de> for HashKeyVisitor {
    type Value = HashOrUuidKey;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a hash key with a valid prefix")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        HashOrUuidKey::from_str(v).map_err(|e| E::custom(e.to_string()))
    }
}

impl Display for HashOrUuidKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HashOrUuidKey::Sha256(inner) => {
                write!(f, "sha256:{}", inner)
            }
            HashOrUuidKey::Sha384(inner) => {
                write!(f, "sha385:{}", inner)
            }
            HashOrUuidKey::Sha512(inner) => {
                write!(f, "sha512:{}", inner)
            }
            HashOrUuidKey::Uuid(inner) => {
                write!(f, "{}", inner.urn())
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
    #[error(transparent)]
    InvalidUuid(uuid::Error),
}

impl FromStr for HashOrUuidKey {
    type Err = HashKeyError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        if let Some((prefix, value)) = key.split_once(':') {
            match prefix {
                "sha256" => Ok(Self::Sha256(value.to_string())),
                "sha384" => Ok(Self::Sha384(value.to_string())),
                "sha512" => Ok(Self::Sha512(value.to_string())),
                "urn" => Ok(Self::Uuid(
                    Uuid::try_parse(key).map_err(HashKeyError::InvalidUuid)?,
                )),
                _ => Err(Self::Err::UnsupportedAlgorithm(prefix.to_string())),
            }
        } else {
            Err(Self::Err::MissingPrefix)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::hash::HashOrUuidKey;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn deserialize() -> Result<(), anyhow::Error> {
        let raw = "sha256:123123";

        let key: HashOrUuidKey = serde_json::from_value(json!("sha256:123123"))?;

        assert_eq!(key, HashOrUuidKey::Sha256("123123".to_string()));

        let _key: HashOrUuidKey =
            serde_json::from_value(json!("urn:uuid:2fd0d1b7-a908-4d63-9310-d57a7f77c6df"))?;

        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), anyhow::Error> {
        let key = HashOrUuidKey::Sha256("123123".to_string());

        let raw = serde_json::to_string(&key)?;

        assert_eq!(raw, "\"sha256:123123\"");
        Ok(())
    }
}
