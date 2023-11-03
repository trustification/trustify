use packageurl::PackageUrl;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Clone, PartialEq)]
pub struct Purl {
    pub ty: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: String,
    pub qualifiers: HashMap<String, String>,
}

impl Hash for Purl {
    fn hash<H: Hasher>(&self, state: &mut H) {
        //state.write(self.package_url.to_string().as_bytes())
        state.write(self.ty.as_bytes());
        if let Some(ns) = &self.namespace {
            state.write(ns.as_bytes())
        }
        state.write(self.name.as_bytes());
        state.write(self.version.as_bytes());
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
            self.qualifiers
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&")
        };

        write!(
            f,
            "pkg://{}{}/{}@{}{}",
            self.ty, ns, self.name, self.version, qualifiers
        )
    }
}

impl Debug for Purl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<&str> for Purl {
    fn from(value: &str) -> Self {
        PackageUrl::from_str(value).unwrap().into()
    }
}

impl From<&&str> for Purl {
    fn from(value: &&str) -> Self {
        PackageUrl::from_str(value).unwrap().into()
    }
}

impl From<String> for Purl {
    fn from(value: String) -> Self {
        value.as_str().into()
    }
}

impl From<&String> for Purl {
    fn from(value: &String) -> Self {
        value.as_str().into()
    }
}

impl From<PackageUrl<'_>> for Purl {
    fn from(value: PackageUrl) -> Self {
        Self {
            ty: value.ty().to_string(),
            namespace: value.namespace().map(|inner| inner.to_string()),
            name: value.name().to_string(),
            version: value.version().unwrap().to_string(),
            qualifiers: value
                .qualifiers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
}
