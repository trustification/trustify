use crate::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::model::advisory::AdvisoryVulnerabilityDetails;
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

impl<'g> AffectedPackageVersionRangeContext<'g> {
    pub fn new(
        advisory_vulnerability: &AdvisoryVulnerabilityContext<'g>,
        affected_package_version_range: affected_package_version_range::Model,
    ) -> Self {
        Self {
            advisory_vulnerability: advisory_vulnerability.clone(),
            affected_package_version_range,
        }
    }
}
