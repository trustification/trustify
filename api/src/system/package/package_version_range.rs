//! Support for a *version range* of a package.

use crate::system::package::PackageContext;
use huevos_entity as entity;
use std::fmt::{Debug, Formatter};


impl From<(&PackageContext, entity::package_version_range::Model)> for PackageVersionRangeContext {
    fn from(
        (package, package_version_range): (&PackageContext, entity::package_version_range::Model),
    ) -> Self {
        Self {
            package: package.clone(),
            package_version_range,
        }
    }
}

impl PackageVersionRangeContext {}

/// Context for package with
#[derive(Clone)]
pub struct PackageVersionRangeContext {
    pub(crate) package: PackageContext,
    pub(crate) package_version_range: entity::package_version_range::Model,
}

impl Debug for PackageVersionRangeContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version_range.fmt(f)
    }
}
