pub mod auth;
pub mod authenticator;
pub mod authorizer;
pub mod client;
pub mod devmode;

#[cfg(feature = "swagger")]
pub mod swagger_ui;

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Debug,
    serde::Deserialize,
    serde::Serialize,
    Hash,
    schemars::JsonSchema,
)]
pub enum Permission {
    #[serde(rename = "create.sbom")]
    CreateSbom,
    #[serde(rename = "read.sbom")]
    ReadSbom,
    #[serde(rename = "update.sbom")]
    UpdateSbom,
    #[serde(rename = "delete.sbom")]
    DeleteSbom,

    #[serde(rename = "create.vex")]
    CreateVex,
    #[serde(rename = "read.vex")]
    ReadVex,
    #[serde(rename = "update.vex")]
    UpdateVex,
    #[serde(rename = "delete.vex")]
    DeleteVex,

    #[serde(rename = "read.cve")]
    ReadCve,

    #[serde(rename = "create.vulnerability")]
    IngestVulnerability,
}

impl AsRef<str> for Permission {
    fn as_ref(&self) -> &str {
        match self {
            Self::CreateSbom => "create.sbom",
            Self::ReadSbom => "read.sbom",
            Self::UpdateSbom => "update.sbom",
            Self::DeleteSbom => "delete.sbom",

            Self::CreateVex => "create.vex",
            Self::ReadVex => "read.vex",
            Self::UpdateVex => "update.vex",
            Self::DeleteVex => "delete.vex",

            Self::ReadCve => "read.cve",

            Self::IngestVulnerability => "create.vulnerability",
        }
    }
}
