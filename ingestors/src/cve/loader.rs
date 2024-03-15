use crate::cve::cve_record::v5::CveRecord;
use crate::hashing::HashingRead;
use crate::Error;
use std::io::Read;
use trustify_common::db::Transactional;
use trustify_graph::graph::Graph;

/// Loader capable of parsing a CVE Record JSON file
/// and manipulating the Graph to integrate it into
/// the knowledge base.
///
/// Should result in ensuring that a *vulnerability*
/// related to the CVE Record exists in the graph, _along with_
/// also ensuring that the CVE *advisory* ends up also
/// in the graph.
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
    ) -> Result<(), Error> {
        let mut reader = HashingRead::new(record);
        let cve: CveRecord = serde_json::from_reader(&mut reader)?;

        self.graph
            .ingest_vulnerability(cve.cve_metadata.cve_id(), Transactional::None)
            .await?;

        let hashes = reader.hashes();

        let sha256 = hex::encode(hashes.sha256.as_ref());

        self.graph
            .ingest_advisory(
                cve.cve_metadata.cve_id(),
                location,
                sha256,
                Transactional::None,
            )
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::cve::loader::CveLoader;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use test_log::test;
    use trustify_common::db::{Database, Transactional};
    use trustify_graph::graph::Graph;

    #[test(tokio::test)]
    async fn cve_loader() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingestors_cve_loader").await?;
        let graph = Graph::new(db);

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../etc/test-data/mitre");

        let cve_json = test_data.join("CVE-2024-28111.json");
        let cve_file = File::open(cve_json)?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2024-28111", Transactional::None)
            .await?;

        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory(
                "CVE-2024-28111",
                "CVE-2024-28111.json",
                "06908108e8097f2a56e628e7814a7bd54a5fc95f645b7c9fab02c1eb8dd9cc0c",
            )
            .await?;

        assert!(loaded_advisory.is_none());

        let loader = CveLoader::new(&graph);

        loader.load("CVE-2024-28111.json", cve_file).await?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2024-28111", Transactional::None)
            .await?;

        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory(
                "CVE-2024-28111",
                "CVE-2024-28111.json",
                "06908108e8097f2a56e628e7814a7bd54a5fc95f645b7c9fab02c1eb8dd9cc0c",
            )
            .await?;

        assert!(loaded_advisory.is_some());

        Ok(())
    }
}
