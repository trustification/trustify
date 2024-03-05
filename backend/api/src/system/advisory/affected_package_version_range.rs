use crate::system::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::system::advisory::AdvisoryContext;
use std::fmt::{Debug, Formatter};
use trustify_entity::affected_package_version_range;
use trustify_entity::affected_package_version_range::Model;

#[derive(Clone)]
pub struct AffectedPackageVersionRangeContext {
    pub(crate) advisory_vulnerability: AdvisoryVulnerabilityContext,
    pub(crate) affected_package_version_range: affected_package_version_range::Model,
}

impl Debug for AffectedPackageVersionRangeContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.affected_package_version_range.fmt(f)
    }
}

impl
    From<(
        &AdvisoryVulnerabilityContext,
        affected_package_version_range::Model,
    )> for AffectedPackageVersionRangeContext
{
    fn from(
        (advisory_vulnerability, affected_package_version_range): (
            &AdvisoryVulnerabilityContext,
            Model,
        ),
    ) -> Self {
        Self {
            advisory_vulnerability: advisory_vulnerability.clone(),
            affected_package_version_range,
        }
    }
}
