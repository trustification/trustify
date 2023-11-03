#![allow(unused)]

use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use packageurl::PackageUrl;
use huevos_common::purl::Purl;

use huevos_entity::package_vulnerability::PackageVulnerability;

pub mod system;

#[derive(Clone, Debug)]
pub struct PackageTree {
    id: i32,
    purl: Purl,
    dependencies: Vec<PackageTree>,
}

#[derive(Clone, Debug)]
pub struct VulnerabilityTree {
    purl: Purl,
    vulnerabilities: Vec<PackageVulnerability>,
    dependencies: Vec<VulnerabilityTree>,
}
