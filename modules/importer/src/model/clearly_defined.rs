use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(
    Serialize, Deserialize, Clone, Debug, PartialEq, Eq, schemars::JsonSchema, ToSchema, Hash,
)]
#[serde(rename_all = "lowercase")]
pub enum ClearlyDefinedPackageType {
    Composer,
    Crate,
    Deb,
    Gem,
    Git,
    Go,
    Maven,
    Npm,
    NuGet,
    Pod,
    Pypi,
}

impl ClearlyDefinedPackageType {
    pub fn all() -> HashSet<Self> {
        HashSet::from([
            Self::Composer,
            Self::Crate,
            Self::Deb,
            Self::Gem,
            Self::Git,
            Self::Go,
            Self::Maven,
            Self::Npm,
            Self::NuGet,
            Self::Pod,
            Self::Pypi,
        ])
    }

    pub fn to_str(&self) -> &str {
        match self {
            ClearlyDefinedPackageType::Composer => "composer",
            ClearlyDefinedPackageType::Crate => "crate",
            ClearlyDefinedPackageType::Deb => "deb",
            ClearlyDefinedPackageType::Gem => "gem",
            ClearlyDefinedPackageType::Git => "git",
            ClearlyDefinedPackageType::Go => "go",
            ClearlyDefinedPackageType::Maven => "maven",
            ClearlyDefinedPackageType::Npm => "npm",
            ClearlyDefinedPackageType::NuGet => "nuget",
            ClearlyDefinedPackageType::Pod => "pod",
            ClearlyDefinedPackageType::Pypi => "pypi",
        }
    }

    pub fn matches(&self, other: &str) -> bool {
        self.to_str() == other
    }
}

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
pub struct ClearlyDefinedImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    #[serde(default = "default::source")]
    pub source: String,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub types: HashSet<ClearlyDefinedPackageType>,
}

pub const DEFAULT_SOURCE_CLEARLY_DEFINED: &str =
    "https://clearlydefinedprod.blob.core.windows.net/changes-notifications";

mod default {
    pub fn source() -> String {
        super::DEFAULT_SOURCE_CLEARLY_DEFINED.into()
    }
}

impl Deref for ClearlyDefinedImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for ClearlyDefinedImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}
