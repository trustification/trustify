//! Support for a *version range* of a package.

use crate::graph::package::PackageContext;
use std::fmt::{Debug, Formatter};
use trustify_entity as entity;

impl<'g> From<(&PackageContext<'g>, entity::package_version_range::Model)>
    for PackageVersionRangeContext<'g>
{
    fn from(
        (package, package_version_range): (
            &PackageContext<'g>,
            entity::package_version_range::Model,
        ),
    ) -> Self {
        Self {
            package: package.clone(),
            package_version_range,
        }
    }
}

impl PackageVersionRangeContext<'_> {}

/// Context for package with
#[derive(Clone)]
pub struct PackageVersionRangeContext<'g> {
    pub(crate) package: PackageContext<'g>,
    pub(crate) package_version_range: entity::package_version_range::Model,
}

impl Debug for PackageVersionRangeContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version_range.fmt(f)
    }
}
