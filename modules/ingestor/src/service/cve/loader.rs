use crate::graph::advisory::{AdvisoryInformation, AdvisoryVulnerabilityInformation};
use crate::graph::vulnerability::VulnerabilityInformation;
use crate::graph::Graph;
use crate::service::{hashing::HashingRead, Error};
use cve::{Cve, Timestamp};
use std::io::Read;
use trustify_common::id::Id;

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

    pub async fn load<L: Into<String>, R: Read>(
        &self,
        location: L,
        record: R,
        checksum: &str,
    ) -> Result<Id, Error> {
        let mut reader = HashingRead::new(record);
        let cve: Cve = serde_json::from_reader(&mut reader)?;
        let id = cve.id();

        let tx = self.graph.transaction().await?;

        let published = cve
            .common_metadata()
            .date_published
            .map(Timestamp::assume_utc);
        let modified = cve
            .common_metadata()
            .date_updated
            .map(Timestamp::assume_utc);

        let (title, assigned, withdrawn, descriptions) = match &cve {
            Cve::Rejected(rejected) => (
                None,
                None,
                rejected.metadata.date_rejected.map(Timestamp::assume_utc),
                &rejected.containers.cna.rejected_reasons,
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
            ),
        };

        let information = VulnerabilityInformation {
            title: title.cloned(),
            published,
            modified,
            withdrawn,
        };

        let vulnerability = self
            .graph
            .ingest_vulnerability(id, information, &tx)
            .await?;

        let mut english_description = None;

        for description in descriptions {
            vulnerability
                .add_description(&description.language, &description.value, &tx)
                .await?;

            if description.language == "en" {
                english_description = Some(description.value.clone());
            }
        }

        let digests = reader.finish().map_err(|e| Error::Generic(e.into()))?;
        let encoded_sha256 = hex::encode(digests.sha256);
        if checksum != encoded_sha256 {
            return Err(Error::Storage(anyhow::Error::msg(
                "document integrity check failed",
            )));
        }

        let information = AdvisoryInformation {
            title: title.cloned(),
            issuer: Some("CVE® (MITRE Corporation".to_string()),
            published,
            modified,
            withdrawn,
        };
        let advisory = self
            .graph
            .ingest_advisory(id, location, encoded_sha256, information, &tx)
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
                }),
                &tx,
            )
            .await?;

        tx.commit().await?;

        Ok(Id::Uuid(advisory.advisory.id))
    }
}

#[cfg(test)]
mod test {
    use crate::graph::Graph;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::{test::TrustifyContext, Transactional};

    use crate::service::cve::loader::CveLoader;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn cve_loader(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);
        let data = include_bytes!("../../../../../etc/test-data/mitre/CVE-2024-28111.json");
        let checksum = "06908108e8097f2a56e628e7814a7bd54a5fc95f645b7c9fab02c1eb8dd9cc0c";

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", ()).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph.get_advisory(checksum, Transactional::None).await?;
        assert!(loaded_advisory.is_none());

        let loader = CveLoader::new(&graph);
        loader
            .load("CVE-2024-28111.json", &data[..], checksum)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", ()).await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph.get_advisory(checksum, Transactional::None).await?;
        assert!(loaded_advisory.is_some());

        let loaded_vulnerability = loaded_vulnerability.unwrap();
        let descriptions = loaded_vulnerability.descriptions("en", ()).await?;
        assert_eq!(1, descriptions.len());
        assert!(descriptions[0]
            .starts_with("Canarytokens helps track activity and actions on a network"));

        Ok(())
    }
}
