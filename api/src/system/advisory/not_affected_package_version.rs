use crate::system::advisory::AdvisoryContext;
use huevos_entity::not_affected_package_version;
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct NotAffectedPackageVersion {
    pub(crate) advisory: AdvisoryContext,
    pub(crate) not_affected_package_version: not_affected_package_version::Model,
}

impl Debug for NotAffectedPackageVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.not_affected_package_version.fmt(f)
    }
}

impl From<(&AdvisoryContext, not_affected_package_version::Model)> for NotAffectedPackageVersion {
    fn from(
        (advisory, not_affected_package_version): (
            &AdvisoryContext,
            not_affected_package_version::Model,
        ),
    ) -> Self {
        Self {
            advisory: advisory.clone(),
            not_affected_package_version,
        }
    }
}
