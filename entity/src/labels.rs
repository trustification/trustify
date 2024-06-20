use async_graphql::scalar;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    sea_orm::FromJsonQueryResult,
)]
pub struct Labels(pub HashMap<String, String>);

scalar!(Labels);

impl Labels {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_one(k: impl Into<String>, v: impl Into<String>) -> Self {
        let mut labels = HashMap::with_capacity(1);
        labels.insert(k.into(), v.into());
        Self(labels)
    }

    pub fn add(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.0.insert(k.into(), v.into());
        self
    }
}

impl<'a> FromIterator<(&'a str, &'a str)> for Labels {
    fn from_iter<T: IntoIterator<Item = (&'a str, &'a str)>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }
}

impl From<()> for Labels {
    fn from(_: ()) -> Self {
        Default::default()
    }
}

impl<const N: usize> From<[(&str, &str); N]> for Labels {
    fn from(value: [(&str, &str); N]) -> Self {
        Self::from_iter(value)
    }
}

impl From<HashMap<String, String>> for Labels {
    fn from(value: HashMap<String, String>) -> Self {
        Self(value)
    }
}

impl<K, V> From<(K, V)> for Labels
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn from((k, v): (K, V)) -> Self {
        let mut value = HashMap::with_capacity(1);
        value.insert(k.as_ref().to_string(), v.as_ref().to_string());
        Self(value)
    }
}

impl Deref for Labels {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Labels {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
