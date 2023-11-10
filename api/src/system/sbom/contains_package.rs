use crate::system::sbom::SbomContext;
use huevos_entity::qualified_package::Model;
use huevos_entity::{qualified_package, sbom_contains_package};
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct SbomContainsPackageContext {
    pub(crate) sbom: SbomContext,
    pub(crate) sbom_contains_package: sbom_contains_package::Model,
}

impl Debug for SbomContainsPackageContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.sbom_contains_package.fmt(f)
    }
}

impl From<(&SbomContext, sbom_contains_package::Model)> for SbomContainsPackageContext {
    fn from((sbom, sbom_contains_package): (&SbomContext, sbom_contains_package::Model)) -> Self {
        Self {
            sbom: sbom.clone(),
            sbom_contains_package,
        }
    }
}
