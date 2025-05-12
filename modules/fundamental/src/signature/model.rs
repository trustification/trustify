use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use trustify_entity::{signature_type::SignatureType, source_document_signature};

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, Eq, PartialEq)]
pub struct Signature {
    pub id: String,
    pub r#type: SignatureType,

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
