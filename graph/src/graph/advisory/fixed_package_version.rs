use crate::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::graph::advisory::AdvisoryContext;
use std::fmt::{Debug, Formatter};
use trustify_entity::fixed_package_version;

#[derive(Clone)]
pub struct FixedPackageVersionContext<'g> {
    pub(crate) advisory_vulnerability: AdvisoryVulnerabilityContext<'g>,
    pub(crate) fixed_package_version: fixed_package_version::Model,
}

impl Debug for FixedPackageVersionContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.fixed_package_version.fmt(f)
    }
}

impl<'g>
    From<(
        &AdvisoryVulnerabilityContext<'g>,
        fixed_package_version::Model,
    )> for FixedPackageVersionContext<'g>
{
    fn from(
        (advisory_vulnerability, fixed_package_version): (
            &AdvisoryVulnerabilityContext<'g>,
            fixed_package_version::Model,
        ),
    ) -> Self {
        Self {
            advisory_vulnerability: advisory_vulnerability.clone(),
            fixed_package_version,
        }
    }
}
