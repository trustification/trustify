use crate::runner::report::ScannerError;
use regex::Regex;
use std::str::FromStr;
use walker_common::utils::url::Urlify;

mod csaf {
    pub use csaf_walker::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
}
mod sbom {
    pub use sbom_walker::discover::{DiscoveredContext, DiscoveredSbom, DiscoveredVisitor};
}

pub struct Filter<T> {
    pub only_patterns: Vec<Regex>,
    pub next: T,
}

impl<T> Filter<T> {
    pub fn from_config(next: T, only_patterns: Vec<String>) -> Result<Self, ScannerError> {
        Ok(Self {
            only_patterns: only_patterns
                .into_iter()
                .map(|r| Regex::from_str(&r))
                .collect::<Result<_, _>>()
                .map_err(|err| ScannerError::Critical(err.into()))?,
            next,
        })
    }

    /// check if the document should be skipped
    ///
    /// return `true` of the document should be skipped, `false` otherwise
    fn skip(&self, document: &impl Urlify) -> bool {
        if self.only_patterns.is_empty() {
            false
        } else {
            let url = document.url();
            let name = if let Some(name) = url.path_segments().into_iter().flatten().last() {
                name
            } else {
                url.path()
            };

            let found = self
                .only_patterns
                .iter()
                .any(|pattern| pattern.is_match(name));

            !found
        }
    }
}

impl<T> csaf::DiscoveredVisitor for Filter<T>
where
    T: csaf::DiscoveredVisitor,
{
    type Error = T::Error;
    type Context = T::Context;

    async fn visit_context(
        &self,
        context: &csaf::DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.next.visit_context(context).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        document: csaf::DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        if !self.skip(&document) {
            self.next.visit_advisory(context, document).await
        } else {
            Ok(())
        }
    }
}

impl<T> sbom::DiscoveredVisitor for Filter<T>
where
    T: sbom::DiscoveredVisitor,
{
    type Error = T::Error;
    type Context = T::Context;

    async fn visit_context(
        &self,
        context: &sbom::DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.next.visit_context(context).await
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        document: sbom::DiscoveredSbom,
    ) -> Result<(), Self::Error> {
        if !self.skip(&document) {
            self.next.visit_sbom(context, document).await
        } else {
            Ok(())
        }
    }
}
