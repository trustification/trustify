use serde_json::Value;

pub trait ContainsSubset {
    // Returns true if the value is a subset of the receiver.
    fn contains_subset(&self, value: Value) -> bool;
}

impl ContainsSubset for Value {
    fn contains_subset(&self, subset: Value) -> bool {
        match (self, &subset) {
            (Value::Object(src), Value::Object(tgt)) => tgt
                .iter()
                .all(|(k, v)| src.get(k).is_some_and(|x| x.contains_subset(v.clone()))),

            (Value::Array(src), Value::Array(subset)) => subset
                .iter()
                .all(|v| src.iter().any(|x| x.contains_subset(v.clone()))),

            _ => subset == *self,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::subset::ContainsSubset;
    use serde_json::json;

    #[test]
    fn test_is_subset() {
        // actual can have additional fields
        let actual = json!({
            "relationship": "PackageOf",
            "other": "test",
        });
        assert!(actual.contains_subset(json!({
                "relationship": "PackageOf",
        })));

        // case where an expected field does not match
        let actual = json!({
            "relationship": "PackageOf",
            "other": "test",
        });
        assert!(!actual.contains_subset(json!({
            "relationship": "bad",
        })));

        // case where an expected field is missing
        let actual = json!({
            "relationship": "PackageOf",
            "other": "test",
        });
        assert!(!actual.contains_subset(json!({
                "name": "SATELLITE-6.15-RHEL-8",
        })));
    }

    #[test]
    fn test_array_subset() {
        // actual can have additional fields
        let actual = json!([1, 2, 3]);
        assert!(actual.contains_subset(json!([2])));

        // other values can be interleaved.
        let actual = json!([1, 2, 3]);
        assert!(actual.contains_subset(json!([1, 3])));

        // case where a value is missing
        let actual = json!([1, 2, 3]);
        assert!(!actual.contains_subset(json!([0])));
    }
}
