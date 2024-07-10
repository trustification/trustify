use crate::{
    graph::{
        advisory::{AdvisoryInformation, AdvisoryVulnerabilityInformation},
        vulnerability::VulnerabilityInformation,
        Graph,
    },
    model::IngestResult,
    service::Error,
};
use cve::{Cve, Timestamp};
use std::io::Read;
use trustify_common::{hashing::Digests, id::Id};
use trustify_entity::labels::Labels;

/// Loader capable of parsing a CVE Record JSON file
/// and manipulating the Graph to integrate it into
/// the knowledge base.
///
/// Should result in ensuring that a *vulnerability*
/// related to the CVE Record exists in the fetch, _along with_
/// also ensuring that the CVE *advisory* ends up also
/// in the fetch.
pub struct CveLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CveLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load<R: Read>(
        &self,
        labels: impl Into<Labels>,
        record: R,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let cve: Cve = serde_json::from_reader(record)?;
        let id = cve.id();
        let labels = labels.into().add("type", "cve");

        let tx = self.graph.transaction().await?;

        let published = cve
            .common_metadata()
            .date_published
            .map(Timestamp::assume_utc);
        let modified = cve
            .common_metadata()
            .date_updated
            .map(Timestamp::assume_utc);

        let (title, assigned, withdrawn, descriptions, cwe, org_name) = match &cve {
            Cve::Rejected(rejected) => (
                None,
                None,
                rejected.metadata.date_rejected.map(Timestamp::assume_utc),
                &rejected.containers.cna.rejected_reasons,
                None,
                rejected
                    .containers
                    .cna
                    .common
                    .provider_metadata
                    .short_name
                    .as_ref(),
            ),
            Cve::Published(published) => (
                published.containers.cna.title.as_ref(),
                published
                    .containers
                    .cna
                    .date_assigned
                    .map(Timestamp::assume_utc),
                None,
                &published.containers.cna.descriptions,
                published
                    .containers
                    .cna
                    .problem_types
                    .iter()
                    .flat_map(|pt| pt.descriptions.iter())
                    .find_map(|d| d.cwe_id.as_ref()),
                published
                    .containers
                    .cna
                    .common
                    .provider_metadata
                    .short_name
                    .as_ref(),
            ),
        };

        let information = VulnerabilityInformation {
            title: title.cloned(),
            published,
            modified,
            withdrawn,
            cwe: cwe.cloned(),
        };

        let vulnerability = self
            .graph
            .ingest_vulnerability(id, information, &tx)
            .await?;

        let mut english_description = None;
        let mut entries = Vec::<(&str, &str)>::new();

        for description in descriptions {
            entries.push((&description.language, &description.value));
            if description.language == "en" {
                english_description = Some(description.value.clone());
            }
        }

        let information = AdvisoryInformation {
            title: title.cloned(),
            issuer: org_name.cloned(),
            published,
            modified,
            withdrawn,
        };
        let advisory = self
            .graph
            .ingest_advisory(id, labels, digests, information, &tx)
            .await?;

        // Link the advisory to the backing vulnerability
        advisory
            .link_to_vulnerability(
                id,
                Some(AdvisoryVulnerabilityInformation {
                    title: title.cloned(),
                    summary: None,
                    description: english_description,
                    discovery_date: assigned,
                    release_date: published,
                    cwe: cwe.cloned(),
                }),
                &tx,
            )
            .await?;

        vulnerability
            .drop_descriptions_for_advisory(advisory.advisory.id, &tx)
            .await?;

        vulnerability
            .add_descriptions(advisory.advisory.id, entries, &tx)
            .await?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(advisory.advisory.id),
            document_id: id.to_string(),
            warnings: vec![],
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::graph::Graph;
    use hex::ToHex;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::Transactional;
    use trustify_common::hashing::Digests;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn cve_loader(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);

        let data = include_bytes!("../../../../../../etc/test-data/mitre/CVE-2024-28111.json");
        let digests = Digests::digest(data);

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", ()).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), Transactional::None)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = CveLoader::new(&graph);
        loader
            .load(("file", "CVE-2024-28111.json"), &data[..], &digests)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", ()).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), Transactional::None)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_vulnerability = loaded_vulnerability.unwrap();
        let descriptions = loaded_vulnerability.descriptions("en", ()).await?;
        assert_eq!(1, descriptions.len());
        assert!(descriptions[0]
            .starts_with("Canarytokens helps track activity and actions on a network"));

        Ok(())
    }
}
