use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use packageurl::PackageUrl;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum PurlErr {
    #[error("missing version {0}")]
    MissingVersion(String),
    #[error("packageurl problem {0}")]
    Package(#[from] packageurl::Error),
}

#[derive(Clone, PartialEq)]
pub struct Purl {
    pub ty: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: HashMap<String, String>,
}

impl Serialize for Purl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl FromStr for Purl {
    type Err = PurlErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PackageUrl::from_str(s)
            .map(Purl::from)
            .map_err(PurlErr::Package)
    }
}
impl<'de> Deserialize<'de> for Purl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PurlVisitor)
    }
}

struct PurlVisitor;

impl<'de> Visitor<'de> for PurlVisitor {
    type Value = Purl;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a pURL")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        v.try_into().map_err(Error::custom)
    }
}

impl Hash for Purl {
    fn hash<H: Hasher>(&self, state: &mut H) {
        //state.write(self.package_url.to_string().as_bytes())
        state.write(self.ty.as_bytes());
        if let Some(ns) = &self.namespace {
            state.write(ns.as_bytes())
        }
        state.write(self.name.as_bytes());
        if let Some(version) = &self.version {
            state.write(&[b'@']);
            state.write(version.as_bytes());
        }
        for (k, v) in &self.qualifiers {
            state.write(k.as_bytes());
            state.write(v.as_bytes());
        }
    }
}

impl Eq for Purl {}

impl Display for Purl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let ns = if let Some(ns) = &self.namespace {
            format!("/{}", ns)
        } else {
            "".to_string()
        };

        let qualifiers = if self.qualifiers.is_empty() {
            "".to_string()
        } else {
            format!(
                "?{}",
                self.qualifiers
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&")
            )
        };

        let version = if let Some(version) = &self.version {
            format!("@{}", version)
        } else {
            "".to_string()
        };

        write!(
            f,
            "pkg://{}{}/{}{}{}",
            self.ty, ns, self.name, version, qualifiers
        )
    }
}

impl Debug for Purl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl TryFrom<&str> for Purl {
    type Error = PurlErr;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match PackageUrl::from_str(value) {
            Ok(s) => Ok(s.into()),
            Err(e) => Err(PurlErr::Package(e)),
        }
    }
}

impl TryFrom<String> for Purl {
    type Error = PurlErr;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl From<PackageUrl<'_>> for Purl {
    fn from(value: PackageUrl) -> Self {
        Self {
            ty: value.ty().to_string(),
            namespace: value.namespace().map(|inner| inner.to_string()),
            name: value.name().to_string(),
            version: value.version().map(|inner| inner.to_string()),
            qualifiers: value
                .qualifiers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::purl::Purl;

    #[test]
    fn purl_serde() {
        let purl: Purl = serde_json::from_str(
            r#"
            "pkg://maven/io.quarkus/quarkus-core@1.2.3?foo=bar"
            "#,
        )
        .unwrap();

        assert_eq!("maven", purl.ty);

        assert_eq!(Some("io.quarkus".to_string()), purl.namespace);

        assert_eq!(Some("1.2.3".to_string()), purl.version);

        assert_eq!(purl.qualifiers.get("foo"), Some(&"bar".to_string()));

        let purl: Purl = "pkg://maven/io.quarkus/quarkus-core@1.2.3?foo=bar"
            .try_into()
            .unwrap();
        let json = serde_json::to_string(&purl).unwrap();

        assert_eq!(
            json,
            r#""pkg://maven/io.quarkus/quarkus-core@1.2.3?foo=bar""#
        );
    }
}
