use crate::system::advisory::AdvisoryContext;
use huevos_entity::cve;
use huevos_entity::cve::Model;
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct AdvisoryCveContext {
    pub(crate) advisory: AdvisoryContext,
    pub(crate) cve: cve::Model,
}

impl Debug for AdvisoryCveContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.cve.fmt(f)
    }
}

impl From<(&AdvisoryContext, cve::Model)> for AdvisoryCveContext {
    fn from((advisory, cve): (&AdvisoryContext, Model)) -> Self {
        Self {
            advisory: advisory.clone(),
            cve,
        }
    }
}
