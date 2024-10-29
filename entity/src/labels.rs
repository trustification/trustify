use async_graphql::scalar;
use std::{
    borrow::Cow,
    collections::HashMap,
    ops::{Deref, DerefMut},
};
use utoipa::{
    openapi::{schema::AdditionalProperties, Object, ObjectBuilder, RefOr, Schema, Type},
    PartialSchema, ToSchema,
};

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    ::serde::Serialize,
    ::serde::Deserialize,
    sea_orm::FromJsonQueryResult,
    schemars::JsonSchema,
)]
pub struct Labels(pub HashMap<String, String>);

impl ToSchema for Labels {
    fn name() -> Cow<'static, str> {
        "Labels".into()
    }
}

impl PartialSchema for Labels {
    fn schema() -> RefOr<Schema> {
        let props = AdditionalProperties::RefOr(Object::with_type(Type::String).into());
        ObjectBuilder::new()
            .additional_properties(Some(props))
            .build()
            .into()
    }
}

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

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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

/// A module to serialize/deserialize labels with a prefix of `.labels`.
///
/// This can be embedded in a struct like this:
///
/// ```rust
/// # use trustify_entity::labels::Labels;
/// #[derive(serde::Deserialize)]
/// struct Example {
///   other_field: String,
///   #[serde(flatten, with="trustify_entity::labels::prefixed")]
///   labels: Labels,
/// }
/// ```
pub mod prefixed {
    use crate::labels::Labels;
    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use serde::{Deserializer, Serializer};
    use std::fmt::Formatter;

    pub fn serialize<S: Serializer>(labels: &Labels, serializer: S) -> Result<S::Ok, S::Error> {
        let mut m = serializer.serialize_map(Some(labels.0.len()))?;
        for (k, v) in &labels.0 {
            m.serialize_key(&format!("labels.{k}"))?;
            m.serialize_value(v)?;
        }
        m.end()
    }

    pub fn deserialize<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Labels, D::Error> {
        deserializer.deserialize_map(PrefixLabelsVisitor { prefix: "labels." })
    }

    struct PrefixLabelsVisitor<'p> {
        prefix: &'p str,
    }

    impl<'p, 'de> Visitor<'de> for PrefixLabelsVisitor<'p> {
        type Value = Labels;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "a map with fields prefixed by {}", self.prefix)
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut result = Labels::new();

            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if let Some(key) = key.strip_prefix(self.prefix) {
                    result.0.insert(key.to_string(), value);
                }
            }

            Ok(result)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

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

    #[derive(Clone, Debug, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
    struct Example {
        foo: String,
        bar: i32,
        #[serde(flatten, with = "super::prefixed")]
        labels: Labels,
    }

    #[test]
    fn parse_labels() {
        assert_eq!(
            Example {
                foo: "bar".to_string(),
                bar: 42,
                labels: Labels::new().add("foo", "bar").add("bar", "42"),
            },
            serde_json::from_value(json!({
                "foo": "bar",
                "bar": 42,
                "labels.foo": "bar",
                "labels.bar": "42",
            }))
            .expect("must parse"),
        );
    }

    #[test]
    fn parse_empty_labels() {
        assert_eq!(
            Example {
                foo: "bar".to_string(),
                bar: 42,
                labels: Labels::new(),
            },
            serde_json::from_value(json!({
                "foo": "bar",
                "bar": 42,
            }))
            .expect("must parse"),
        );
    }

    #[test]
    fn serialize_labels() {
        assert_eq!(
            serde_json::to_value(Example {
                foo: "bar".to_string(),
                bar: 42,
                labels: Labels::new().add("foo", "bar").add("bar", "42"),
            })
            .expect("must serialize"),
            json!({
                "foo": "bar",
                "bar": 42,
                "labels.foo": "bar",
                "labels.bar": "42",
            }),
        );
    }
}
