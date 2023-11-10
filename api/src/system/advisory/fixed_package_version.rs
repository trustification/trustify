use crate::system::advisory::AdvisoryContext;
use huevos_entity::fixed_package_version;
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct FixedPackageVersionContext {
    pub(crate) advisory: AdvisoryContext,
    pub(crate) fixed_package_version: fixed_package_version::Model,
}

impl Debug for FixedPackageVersionContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.fixed_package_version.fmt(f)
    }
}

impl From<(&AdvisoryContext, fixed_package_version::Model)> for FixedPackageVersionContext {
    fn from(
        (advisory, fixed_package_version): (&AdvisoryContext, fixed_package_version::Model),
    ) -> Self {
        Self {
            advisory: advisory.clone(),
            fixed_package_version,
        }
    }
}
