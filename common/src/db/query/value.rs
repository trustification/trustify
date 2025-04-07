use chrono::{Local, NaiveDateTime};
use human_date_parser::{ParseResult, from_human_time};
use std::cmp::Ordering;
use time::OffsetDateTime;

pub trait Valuable: PartialOrd<String> {
    fn like(&self, pat: &str) -> bool;
}

pub enum Value<'a> {
    String(&'a str),
    Int(i32),
    Float(f64),
    Date(&'a OffsetDateTime),
    Array(Vec<Value<'a>>),
    Custom(&'a dyn Valuable),
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
            Self::String(s) => s.partial_cmp(&rhs.as_str()),
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

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use super::*;
    use std::collections::HashMap;
    use test_log::test;

    #[test(tokio::test)]
    async fn filter_values() -> Result<(), anyhow::Error> {
        use time::format_description::well_known::Rfc2822;
        let now = time::OffsetDateTime::now_utc();
        let then = OffsetDateTime::parse("Sat, 12 Jun 1993 13:25:19 GMT", &Rfc2822)?;
        let context = HashMap::from([
            ("id", Value::String("foo")),
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
    async fn filter_array_values() -> Result<(), anyhow::Error> {
        use crate::purl::Purl;

        let purl = Purl::from_str("pkg:x/foo").unwrap();
        let purls = vec![Value::Custom(&purl), Value::String("pkg:x/bar")];
        let context = HashMap::from([("purl", Value::Array(purls))]);

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
}
