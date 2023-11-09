use crate::system::advisory::AdvisoryContext;
use huevos_entity::affected_package_version_range;
use huevos_entity::affected_package_version_range::Model;
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct AffectedPackageVersionRangeContext {
    pub(crate) advisory: AdvisoryContext,
    pub(crate) affected_package_version_range: affected_package_version_range::Model,
}

impl Debug for AffectedPackageVersionRangeContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.affected_package_version_range.fmt(f)
    }
}

impl From<(&AdvisoryContext, affected_package_version_range::Model)>
    for AffectedPackageVersionRangeContext
{
    fn from((advisory, affected_package_version_range): (&AdvisoryContext, Model)) -> Self {
        Self {
            advisory: advisory.clone(),
            affected_package_version_range,
        }
    }
}
