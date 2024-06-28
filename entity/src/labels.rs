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
    utoipa::ToSchema,
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

    pub fn extend<I, K, V>(mut self, i: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.0
            .extend(i.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Apply a label update.
    ///
    /// This will apply the provided update to the current set of labels. Updates with an empty
    /// value will remove the label.
    pub fn apply(mut self, update: Labels) -> Self {
        for (k, v) in update.0 {
            if v.is_empty() {
                self.remove(&k);
            } else {
                self.insert(k, v);
            }
        }
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn apply_update() {
        let original = Labels::new().extend([("foo", "1"), ("bar", "2")]);
        let modified =
            original.apply(Labels::new().extend([("foo", "2"), ("bar", ""), ("baz", "3")]));

        assert_eq!(
            modified.0,
            HashMap::from_iter([
                ("foo".to_string(), "2".to_string()),
                ("baz".to_string(), "3".to_string())
            ])
        );
    }
}
