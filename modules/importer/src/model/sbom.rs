use super::*;
use trustify_common::{model::BinaryByteSize, serde::is_default};

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct SbomImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    pub source: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<Url>,

    #[serde(default)]
    pub v3_signatures: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_patterns: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<BinaryByteSize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_retries: Option<usize>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub ignore_missing: bool,
}

impl Deref for SbomImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for SbomImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn serde() {
        let json = json!({
            "disabled": false,
            "period": "30s",
            "source": "https://redhat.com",
            "v3Signatures": false,
            "sizeLimit": "1234 Mi",
        });
        let sbom: SbomImporter = serde_json::from_value(json.clone()).expect("must deserialize");

        assert_eq!(
            sbom,
            SbomImporter {
                common: CommonImporter {
                    disabled: false,
                    period: Duration::from_secs(30),
                    description: None,
                    labels: Default::default(),
                },
                source: "https://redhat.com".to_string(),
                keys: vec![],
                v3_signatures: false,
                only_patterns: vec![],
                size_limit: Some(bytesize::ByteSize::mib(1234).into()),
                fetch_retries: None,
                ignore_missing: false,
            }
        );

        assert_eq!(
            json!({
                "disabled": false,
                "period": "30s",
                "source": "https://redhat.com",
                "v3Signatures": false,
                "sizeLimit": "1.2 GiB",
            }),
            serde_json::to_value(&sbom).expect("must serialize")
        );
    }
}
