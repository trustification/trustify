use std::cmp::Ordering;
use time::OffsetDateTime;

pub trait Value {
    fn like(&self, pat: &str) -> bool;
    fn compare(&self, other: &str) -> Option<Ordering>;
}

impl Value for &str {
    fn like(&self, pat: &str) -> bool {
        str::contains(self, pat)
    }
    fn compare(&self, other: &str) -> Option<Ordering> {
        (*self).partial_cmp(other)
    }
}

impl Value for String {
    fn like(&self, pat: &str) -> bool {
        self.as_str().contains(pat)
    }
    fn compare(&self, other: &str) -> Option<Ordering> {
        self.as_str().partial_cmp(other)
    }
}

impl<T: Value> Value for Vec<T> {
    fn like(&self, pat: &str) -> bool {
        self.iter().any(|v| v.like(pat))
    }
    fn compare(&self, other: &str) -> Option<Ordering> {
        if self
            .iter()
            .any(|v| matches!(v.compare(other), Some(Ordering::Equal)))
        {
            Some(Ordering::Equal)
        } else {
            None
        }
    }
}

impl Value for i32 {
    fn like(&self, _: &str) -> bool {
        false
    }
    fn compare(&self, other: &str) -> Option<Ordering> {
        match other.parse::<i32>() {
            Ok(i) => self.partial_cmp(&i),
            _ => None,
        }
    }
}

impl Value for f64 {
    fn like(&self, _: &str) -> bool {
        false
    }
    fn compare(&self, other: &str) -> Option<Ordering> {
        match other.parse::<f64>() {
            Ok(i) => self.partial_cmp(&i),
            _ => None,
        }
    }
}

impl Value for OffsetDateTime {
    fn like(&self, pat: &str) -> bool {
        self.to_string().contains(pat)
    }
    fn compare(&self, rhs: &str) -> Option<Ordering> {
        use chrono::{Local, NaiveDateTime};
        use human_date_parser::{ParseResult, from_human_time};
        match from_human_time(&self.to_string()) {
            Ok(ParseResult::DateTime(field)) => match from_human_time(rhs) {
                Ok(ParseResult::DateTime(other)) => field.partial_cmp(&other),
                Ok(ParseResult::Date(d)) => {
                    let other = NaiveDateTime::new(d, field.time())
                        .and_local_timezone(Local)
                        .unwrap();
                    field.partial_cmp(&other)
                }
                Ok(ParseResult::Time(t)) => {
                    let other = NaiveDateTime::new(field.date_naive(), t)
                        .and_local_timezone(Local)
                        .unwrap();
                    field.partial_cmp(&other)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

pub(crate) struct OrderedValue<'a>(pub &'a dyn Value);

impl PartialEq<String> for OrderedValue<'_> {
    fn eq(&self, other: &String) -> bool {
        matches!(self.0.compare(other), Some(Ordering::Equal))
    }
}
impl PartialOrd<String> for OrderedValue<'_> {
    fn partial_cmp(&self, other: &String) -> Option<Ordering> {
        self.0.compare(other)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use super::*;
    use std::collections::HashMap;
    use test_log::test;
    use time::OffsetDateTime;

    #[test(tokio::test)]
    async fn filter_values() -> Result<(), anyhow::Error> {
        use time::format_description::well_known::Rfc2822;
        let now = OffsetDateTime::now_utc();
        let then = OffsetDateTime::parse("Sat, 12 Jun 1993 13:25:19 GMT", &Rfc2822)?;

        // To avoid heap allocation and simplify lifetimes, every type
        // is by reference, even &str's and primitives
        let mut context: HashMap<&str, Box<&dyn Value>> = HashMap::new();
        context.insert("id", Box::new(&"foo"));
        context.insert("count", Box::new(&42));
        context.insert("score", Box::new(&6.66));
        context.insert("detected", Box::new(&then));
        context.insert("published", Box::new(&now));

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
        let purls = vec!["pkg:x/foo", "pkg:x/bar"];
        let mut context: HashMap<&str, Box<&dyn Value>> = HashMap::new();
        context.insert("purl", Box::new(&purls));

        assert!(q("purl=pkg:x/foo").apply(&context));
        assert!(!q("purl!=pkg:x/foo").apply(&context));
        assert!(q("purl~pkg:x").apply(&context));
        assert!(q("purl!~pkg:y").apply(&context));
        assert!(q("purl~foo").apply(&context));
        assert!(q("purl!~baz").apply(&context));

        assert!(q("pkg:x/foo").apply(&context));
        assert!(q("pkg:x/bar").apply(&context));
        assert!(q("foo|bar").apply(&context));
        assert!(!q("bizz|buzz").apply(&context));

        Ok(())
    }
}
