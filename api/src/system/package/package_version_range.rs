use huevos_entity::package_version_range;
use crate::system::package::{PackageContext, PackageVersionRangeContext};

impl From<(&PackageContext, package_version_range::Model)> for PackageVersionRangeContext {
    fn from(
        (package, package_version_range): (&PackageContext, package_version_range::Model),
    ) -> Self {
        Self {
            package: package.clone(),
            package_version_range,
        }
    }
}

impl PackageVersionRangeContext {}
