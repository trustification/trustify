use crate::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::graph::advisory::AdvisoryContext;
use std::fmt::{Debug, Formatter};
use trustify_entity::not_affected_package_version;

#[derive(Clone)]
pub struct NotAffectedPackageVersionContext<'g> {
    pub(crate) advisory_vulnerability: AdvisoryVulnerabilityContext<'g>,
    pub(crate) not_affected_package_version: not_affected_package_version::Model,
}

impl Debug for NotAffectedPackageVersionContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.not_affected_package_version.fmt(f)
    }
}

impl<'g>
    From<(
        &AdvisoryVulnerabilityContext<'g>,
        not_affected_package_version::Model,
    )> for NotAffectedPackageVersionContext<'g>
{
    fn from(
        (advisory_vulnerability, not_affected_package_version): (
            &AdvisoryVulnerabilityContext<'g>,
            not_affected_package_version::Model,
        ),
    ) -> Self {
        Self {
            advisory_vulnerability: advisory_vulnerability.clone(),
            not_affected_package_version,
        }
    }
}
