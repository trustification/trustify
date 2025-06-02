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
    #[allow(clippy::result_large_err)]
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

#[cfg(test)]
mod test {
    use super::*;
    use csaf_walker::discover::{DiscoveredAdvisory, DiscoveredVisitor, DistributionContext};
    use parking_lot::Mutex;
    use sbom_walker::discover::DiscoveredVisitor as _;
    use std::{sync::Arc, time::SystemTime};
    use test_log::test;
    use url::Url;

    #[derive(Clone, Debug, Default)]
    struct MockVisitor {
        pub found: Arc<Mutex<Vec<String>>>,
    }

    impl sbom::DiscoveredVisitor for MockVisitor {
        type Error = anyhow::Error;
        type Context = ();

        async fn visit_context(
            &self,
            _context: &sbom::DiscoveredContext<'_>,
        ) -> Result<Self::Context, Self::Error> {
            Ok(())
        }

        async fn visit_sbom(
            &self,
            _context: &Self::Context,
            sbom: sbom::DiscoveredSbom,
        ) -> Result<(), Self::Error> {
            let mut found = self.found.lock();
            found.push(sbom.url.to_string());
            Ok(())
        }
    }

    impl csaf::DiscoveredVisitor for MockVisitor {
        type Error = anyhow::Error;
        type Context = ();

        async fn visit_context(
            &self,
            _context: &csaf::DiscoveredContext<'_>,
        ) -> Result<Self::Context, Self::Error> {
            Ok(())
        }

        async fn visit_advisory(
            &self,
            _context: &Self::Context,
            advisory: DiscoveredAdvisory,
        ) -> Result<(), Self::Error> {
            let mut found = self.found.lock();
            found.push(advisory.url.to_string());
            Ok(())
        }
    }

    fn mock_sbom(url: &str) -> sbom::DiscoveredSbom {
        sbom::DiscoveredSbom {
            url: Url::parse(url).unwrap(),
            modified: SystemTime::now(),
        }
    }

    fn mock_advisory(url: &str) -> csaf::DiscoveredAdvisory {
        csaf::DiscoveredAdvisory {
            context: Arc::new(DistributionContext::Directory(
                Url::parse("https://foo/bar").unwrap(),
            )),
            url: Url::parse(url).unwrap(),
            digest: None,
            signature: None,
            modified: SystemTime::now(),
        }
    }

    #[test(tokio::test)]
    async fn filter_none() {
        let mock = MockVisitor::default();

        let filter = Filter {
            only_patterns: vec![],
            next: mock.clone(),
        };

        filter
            .visit_sbom(&(), mock_sbom("https://foo/bar/baz.json"))
            .await
            .unwrap();

        assert_eq!(
            *mock.found.lock(),
            vec!["https://foo/bar/baz.json".to_string(),]
        );
    }

    #[test(tokio::test)]
    async fn filter() {
        let mock = MockVisitor::default();

        let filter = Filter {
            only_patterns: vec![Regex::from_str(r#".*\.json$"#).unwrap()],
            next: mock.clone(),
        };

        for i in [
            "https://foo/bar/baz.json",
            "https://foo/bar/baz.xml",
            "https://foo/bar.json/baz.xml",
        ] {
            filter.visit_sbom(&(), mock_sbom(i)).await.unwrap();
            filter.visit_advisory(&(), mock_advisory(i)).await.unwrap();
        }

        assert_eq!(
            *mock.found.lock(),
            vec![
                "https://foo/bar/baz.json".to_string(),
                "https://foo/bar/baz.json".to_string()
            ]
        );
    }
}
