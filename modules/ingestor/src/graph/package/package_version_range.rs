//! Support for a *version range* of a package.

use crate::graph::package::PackageContext;
use std::fmt::{Debug, Formatter};
use trustify_entity as entity;
use trustify_entity::package_version_range;

impl<'g> PackageVersionRangeContext<'g> {
    pub fn new(
        package: &PackageContext<'g>,
        package_version_range: package_version_range::Model,
    ) -> Self {
        Self {
            package: package.clone(),
            package_version_range,
        }
    }
}

/// Context for package with
#[derive(Clone)]
pub struct PackageVersionRangeContext<'g> {
    pub package: PackageContext<'g>,
    pub package_version_range: entity::package_version_range::Model,
}

impl Debug for PackageVersionRangeContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version_range.fmt(f)
    }
}
