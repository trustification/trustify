#![allow(unused)]
#![allow(clippy::module_inception)]

use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use packageurl::PackageUrl;
use trustify_common::purl::Purl;

pub mod system;

pub mod db;
