use crate::system::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::system::advisory::AdvisoryContext;
use huevos_entity::not_affected_package_version;
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct NotAffectedPackageVersionContext {
    pub(crate) advisory_vulnerability: AdvisoryVulnerabilityContext,
    pub(crate) not_affected_package_version: not_affected_package_version::Model,
}

impl Debug for NotAffectedPackageVersionContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.not_affected_package_version.fmt(f)
    }
}

impl
    From<(
        &AdvisoryVulnerabilityContext,
        not_affected_package_version::Model,
    )> for NotAffectedPackageVersionContext
{
    fn from(
        (advisory_vulnerability, not_affected_package_version): (
            &AdvisoryVulnerabilityContext,
            not_affected_package_version::Model,
        ),
    ) -> Self {
        Self {
            advisory_vulnerability: advisory_vulnerability.clone(),
            not_affected_package_version,
        }
    }
}
