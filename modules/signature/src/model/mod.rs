use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use trustify_common::model::Revisioned;
use trustify_entity::{signature_type::SignatureType, source_document_signature, trust_anchor};

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, Eq, PartialEq)]
pub struct Signature {
    /// The internal ID of the signature entry
    pub id: String,
    /// The signature type
    pub r#type: SignatureType,

    /// The signature payload
    #[serde_as(as = "serde_with::base64::Base64")]
    pub payload: Vec<u8>,
}

impl From<source_document_signature::Model> for Signature {
    fn from(value: source_document_signature::Model) -> Self {
        Self {
            id: value.id.to_string(),
            r#type: value.r#type,
            payload: value.payload,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrustAnchor {
    /// The internal ID
    pub id: String,

    #[serde(flatten)]
    pub data: TrustAnchorData,
}

impl From<trust_anchor::Model> for TrustAnchor {
    fn from(value: trust_anchor::Model) -> Self {
        let trust_anchor::Model {
            id,
            revision: _,
            disabled,
            description,
            r#type,
            payload,
        } = value;

        Self {
            id,
            data: TrustAnchorData {
                disabled,
                description,
                r#type,
                payload,
            },
        }
    }
}

impl TrustAnchor {
    pub fn from_revisioned(value: trust_anchor::Model) -> Revisioned<Self> {
        let revision = value.revision.to_string();
        Revisioned {
            revision,
            value: value.into(),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrustAnchorData {
    /// A flag if this entry should be considered when finding a trust anchor for validating signatures
    #[serde(default)]
    pub disabled: bool,
    /// A human-readable description
    #[serde(default)]
    pub description: String,
    /// The type of signatures this trust anchor is used for
    pub r#type: SignatureType,
    /// The actual payload
    ///
    /// This is most likely a root certificate, depending on the signature type.
    #[serde_as(as = "serde_with::base64::Base64")]
    pub payload: Vec<u8>,
}
