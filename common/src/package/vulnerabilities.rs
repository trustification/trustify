use sea_orm::entity::prelude::DateTimeWithTimeZone;
use sea_orm::FromQueryResult;
use serde::{Deserialize, Serialize};

#[derive(FromQueryResult, Debug, Clone, Serialize, Deserialize)]
pub struct PackageVulnerability {
    pub identifier: String,
    pub source: String,
    pub timestamp: DateTimeWithTimeZone,
}

#[derive(FromQueryResult, Debug)]
pub struct TaggedPackageVulnerability {
    pub package_id: i32,
    pub identifier: String,
    pub source: String,
    pub timestamp: DateTimeWithTimeZone,
}
