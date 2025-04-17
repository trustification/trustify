use chrono::{Local, NaiveDateTime};
use human_date_parser::{ParseResult, from_human_time};
use std::{cmp::Ordering, collections::HashMap};
use time::OffsetDateTime;

#[derive(Clone)]
pub enum Value<'a> {
    String(String),
    Int(i32),
    Float(f64),
    Date(&'a OffsetDateTime),
    Array(Vec<Value<'a>>),
    Custom(&'a dyn Valuable),
}

pub struct ValueContext<'a> {
    values: HashMap<String, Value<'a>>,
    nested: HashMap<String, HashMap<String, Value<'a>>>,
}

pub trait Context {
    fn get(&self, key: &str) -> Option<&Value>;
    fn values(&self) -> impl Iterator<Item = &Value>;
}

pub trait Valuable: PartialOrd<String> {
    fn like(&self, pat: &str) -> bool;
}

impl Valuable for Value<'_> {
    fn like(&self, pat: &str) -> bool {
        match self {
            Self::String(s) => s.contains(pat),
            Self::Date(d) => d.to_string().contains(pat),
            Self::Array(a) => a.iter().any(|v| v.like(pat)),
            Self::Custom(v) => v.like(pat),
            Self::Int(_) | Self::Float(_) => false,
        }
    }
}

impl PartialEq<String> for Value<'_> {
    fn eq(&self, other: &String) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Equal))
    }
}

impl PartialOrd<String> for Value<'_> {
    fn partial_cmp(&self, rhs: &String) -> Option<Ordering> {
        match self {
            Self::String(s) => s.partial_cmp(rhs),
            Self::Int(v) => match rhs.parse::<i32>() {
                Ok(i) => v.partial_cmp(&i),
                _ => None,
            },
            Self::Float(v) => match rhs.parse::<f64>() {
                Ok(i) => v.partial_cmp(&i),
                _ => None,
            },
            Self::Date(v) => {
                let now = Local::now().naive_local();
                match from_human_time(&v.to_string(), now) {
                    Ok(ParseResult::DateTime(field)) => match from_human_time(rhs, now) {
                        Ok(ParseResult::DateTime(other)) => field.partial_cmp(&other),
                        Ok(ParseResult::Date(d)) => {
                            let other = NaiveDateTime::new(d, field.time());
                            field.partial_cmp(&other)
                        }
                        Ok(ParseResult::Time(t)) => {
                            let other = NaiveDateTime::new(field.date(), t);
                            field.partial_cmp(&other)
                        }
                        _ => None,
                    },
                    _ => None,
                }
            }
            Self::Array(arr) => {
                if arr.iter().any(|v| v.eq(rhs)) {
                    Some(Ordering::Equal)
                } else if arr.iter().all(|v| v.gt(rhs)) {
                    Some(Ordering::Greater)
                } else if arr.iter().all(|v| v.lt(rhs)) {
                    Some(Ordering::Less)
                } else {
                    None
                }
            }
            Self::Custom(v) => v.partial_cmp(&rhs),
        }
    }
}

impl<'a, T: Valuable> From<&'a Vec<T>> for Value<'a> {
    fn from(v: &'a Vec<T>) -> Self {
        Value::Array(v.iter().map(|v| Value::Custom(v)).collect())
    }
}

impl Context for &ValueContext<'_> {
    fn get(&self, key: &str) -> Option<&Value> {
        self.values.get(key).or_else(|| {
            key.split_once(':')
                .and_then(|(k, v)| self.nested.get(k).and_then(|m| m.get(v)))
        })
    }
    fn values(&self) -> impl Iterator<Item = &Value> {
        self.values
            .values()
            .chain(self.nested.values().flat_map(|m| m.values()))
    }
}

impl Default for ValueContext<'_> {
    fn default() -> Self {
        let values = HashMap::default();
        let nested = HashMap::default();
        Self { values, nested }
    }
}

impl<'a> ValueContext<'a> {
    pub fn put_string<S: Into<String>>(&mut self, key: S, value: S) {
        self.values.insert(key.into(), Value::String(value.into()));
    }
    pub fn put_int<K: Into<String>>(&mut self, key: K, value: i32) {
        self.values.insert(key.into(), Value::Int(value));
    }
    pub fn put_float<K: Into<String>>(&mut self, key: K, value: f64) {
        self.values.insert(key.into(), Value::Float(value));
    }
    pub fn put_date<K: Into<String>>(&mut self, key: K, value: &'a OffsetDateTime) {
        self.values.insert(key.into(), Value::Date(value));
    }
    pub fn put_array<K: Into<String>>(&mut self, key: K, value: Vec<Value<'a>>) {
        self.values.insert(key.into(), Value::Array(value));
    }
    pub fn put_value<K: Into<String>>(&mut self, key: K, value: Value<'a>) {
        self.values.insert(key.into(), value);
    }

    // Maintain a shallow nesting of values to support colon-delimited
    // fields. When keys are re-inserted into the nested map, the
    // existing string values are not overwritten; they are converted
    // to array values.
    pub fn put_nested<K, V>(&mut self, key: K, values: V)
    where
        K: AsRef<str>,
        V: Iterator<Item = (String, String)>,
    {
        for (k, v) in values {
            self.nested
                .entry(key.as_ref().to_string())
                .and_modify(|m| {
                    m.entry(k.clone())
                        .and_modify(|val| match val {
                            Value::Array(arr) => {
                                arr.push(Value::String(v.clone()));
                            }
                            _ => *val = Value::Array(vec![val.clone(), Value::String(v.clone())]),
                        })
                        .or_insert(Value::String(v.clone()));
                })
                .or_insert(HashMap::from([(k, Value::String(v))]));
        }
    }

    // Convenient initialization
    pub fn from<K: AsRef<str>, const N: usize>(arr: [(K, Value<'a>); N]) -> Self {
        Self {
            values: HashMap::from(arr.map(|(k, v)| (k.as_ref().to_string(), v))),
            ..Default::default()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use super::*;
    use test_log::test;

    #[test(tokio::test)]
    async fn filter_values() -> Result<(), anyhow::Error> {
        use time::format_description::well_known::Rfc2822;
        let now = time::OffsetDateTime::now_utc();
        let then = OffsetDateTime::parse("Sat, 12 Jun 1993 13:25:19 GMT", &Rfc2822)?;
        let context = ValueContext::from([
            ("id", Value::String("foo".into())),
            ("count", Value::Int(42)),
            ("score", Value::Float(6.66)),
            ("detected", Value::Date(&then)),
            ("published", Value::Date(&now)),
        ]);
        assert!(q("oo|aa|bb&count<100&count>10&id=foo").apply(&context));
        assert!(q("score=6.66").apply(&context));
        assert!(q("count>=42&count<=42").apply(&context));
        assert!(q("published>2 days ago&published<next week").apply(&context));

        assert!(q("detected=1993-06-12").apply(&context));
        assert!(q("detected>13:20:00").apply(&context));
        assert!(q("detected~1993").apply(&context));
        assert!(q("1993").apply(&context));

        assert!(q(&format!("published={}", now)).apply(&context));
        assert!(q(&format!("published={}", now.date())).apply(&context));
        assert!(q(&format!("published={}", now.time())).apply(&context));
        assert!(q(&format!("published>=today {}", now.time())).apply(&context));
        assert!(q(&format!("published>={}", now)).apply(&context));
        assert!(q(&format!("published<={}", now.date())).apply(&context));
        assert!(q(&format!("published~{}", now.time())).apply(&context));

        Ok(())
    }

    #[test(tokio::test)]
    async fn filter_array_custom_values() -> Result<(), anyhow::Error> {
        use crate::purl::Purl;

        let purl = Purl::from_str("pkg:x/foo").unwrap();
        let purls = vec![Value::Custom(&purl), Value::String("pkg:x/bar".into())];
        let context = ValueContext::from([("purl", Value::Array(purls))]);

        assert!(q("purl=pkg:x/foo").apply(&context));
        assert!(!q("purl!=pkg:x/foo").apply(&context));
        assert!(q("purl~pkg:x").apply(&context));
        assert!(q("purl!~pkg:y").apply(&context));
        assert!(q("purl~foo").apply(&context));
        assert!(q("purl!~baz").apply(&context));
        assert!(q("purl<pkg:y/foo").apply(&context));
        assert!(q("purl>pkg:w/foo").apply(&context));
        assert!(q("purl<pkg:y").apply(&context));
        assert!(q("purl>pkg:w").apply(&context));

        assert!(q("pkg:x/foo").apply(&context));
        assert!(q("pkg:x/bar").apply(&context));
        assert!(q("foo|bar").apply(&context));
        assert!(!q("bizz|buzz").apply(&context));

        Ok(())
    }

    #[test(tokio::test)]
    async fn filter_nested_values() -> Result<(), anyhow::Error> {
        use crate::purl::Purl;

        let purl = Purl::from_str("pkg:rpm/foo@1.0?k1=v1&k2=v2")?;
        let parts = HashMap::from(
            [("ty", "rpm"), ("name", "foo"), ("version", "1.0")]
                .map(|(k, v)| (k.to_string(), v.to_string())),
        );
        let other = HashMap::from(
            [("ty", "maven"), ("name", "bar"), ("version", "42")]
                .map(|(k, v)| (k.to_string(), v.to_string())),
        );

        let mut context = ValueContext::from([("purl", Value::Custom(&purl))]);
        context.put_nested("qualifiers", purl.qualifiers.clone().into_iter());
        context.put_nested("purl", parts.into_iter());
        context.put_nested("purl", other.into_iter()); // shouldn't overwrite

        assert!(q("purl~pkg:rpm/foo").apply(&context));
        assert!(q("qualifiers:k1=v1").apply(&context));
        assert!(q("qualifiers:k2!=v1").apply(&context));
        assert!(!q("qualifiers:missing!=anything").apply(&context));
        assert!(q("purl:name=foo").apply(&context));
        assert!(q("purl:version=1.0").apply(&context));
        assert!(q("purl:version=42").apply(&context));
        assert!(!q("purl:version<1").apply(&context));

        Ok(())
    }
}
