use crate::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::graph::advisory::AdvisoryContext;
use std::fmt::{Debug, Formatter};
use trustify_entity::affected_package_version_range;
use trustify_entity::affected_package_version_range::Model;

#[derive(Clone)]
pub struct AffectedPackageVersionRangeContext<'g> {
    pub(crate) advisory_vulnerability: AdvisoryVulnerabilityContext<'g>,
    pub(crate) affected_package_version_range: affected_package_version_range::Model,
}

impl Debug for AffectedPackageVersionRangeContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.affected_package_version_range.fmt(f)
    }
}

impl<'g>
    From<(
        &AdvisoryVulnerabilityContext<'g>,
        affected_package_version_range::Model,
    )> for AffectedPackageVersionRangeContext<'g>
{
    fn from(
        (advisory_vulnerability, affected_package_version_range): (
            &AdvisoryVulnerabilityContext<'g>,
            Model,
        ),
    ) -> Self {
        Self {
            advisory_vulnerability: advisory_vulnerability.clone(),
            affected_package_version_range,
        }
    }
}
