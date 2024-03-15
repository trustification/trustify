use async_trait::async_trait;
use regex::Regex;
use sbom_walker::discover::{DiscoveredContext, DiscoveredSbom, DiscoveredVisitor};

pub struct Filter<T> {
    pub only_patterns: Vec<Regex>,
    pub next: T,
}

#[async_trait(?Send)]
impl<T> DiscoveredVisitor for Filter<T>
where
    T: DiscoveredVisitor,
{
    type Error = T::Error;
    type Context = T::Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext,
    ) -> Result<Self::Context, Self::Error> {
        self.next.visit_context(context).await
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        sbom: DiscoveredSbom,
    ) -> Result<(), Self::Error> {
        if !self.only_patterns.is_empty() {
            let name = if let Some(name) = sbom.url.path_segments().into_iter().flatten().last() {
                name
            } else {
                sbom.url.path()
            };

            let found = self
                .only_patterns
                .iter()
                .any(|pattern| pattern.is_match(name));

            if !found {
                // do not pass to the next, return now
                return Ok(());
            }
        }

        self.next.visit_sbom(context, sbom).await
    }
}
