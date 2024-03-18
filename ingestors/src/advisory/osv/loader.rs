use std::io::Read;

use trustify_graph::graph::Graph;

use crate::advisory::osv::schema::Vulnerability;
use crate::hashing::HashingRead;
use crate::Error;

pub struct OsvLoader<'g> {
    graph: &'g Graph,
}

impl<'g> OsvLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load<L: Into<String>, R: Read>(
        &self,
        location: L,
        record: R,
    ) -> Result<(), Error> {
        let mut reader = HashingRead::new(record);
        let osv: Vulnerability = serde_json::from_reader(&mut reader)?;

        let tx = self.graph.transaction().await?;

        if let Some(cve_ids) = &osv.aliases.map(|aliases| {
            aliases
                .iter()
                .filter(|e| e.starts_with("CVE-"))
                .cloned()
                .collect::<Vec<_>>()
        }) {
            let hashes = reader.hashes();
            let sha256 = hex::encode(hashes.sha256.as_ref());

            let advisory = self
                .graph
                .ingest_advisory(osv.id, location, sha256, &tx)
                .await?;

            for cve_id in cve_ids {
                advisory.ingest_vulnerability(cve_id, &tx).await?;
            }
        }

        tx.commit().await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;

    use test_log::test;

    use trustify_common::db::{Database, Transactional};
    use trustify_graph::graph::Graph;

    use crate::advisory::osv::loader::OsvLoader;

    #[test(tokio::test)]
    async fn loader() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingestors_osv_loader").await?;
        let graph = Graph::new(db);

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../etc/test-data/osv");

        let osv_json = test_data.join("RUSTSEC-2021-0079.json");
        let osv_file = File::open(osv_json)?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2021-32714", Transactional::None)
            .await?;

        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory(
                "RUSTSEC-2021-0079",
                "RUSTSEC-2021-0079.json",
                "d113c2bd1ad6c3ac00a3a8d3f89d3f38de935f8ede0d174a55afe9911960cf51",
            )
            .await?;

        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);

        loader.load("RUSTSEC-2021-0079.json", osv_file).await?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2021-32714", Transactional::None)
            .await?;

        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory(
                "RUSTSEC-2021-0079",
                "RUSTSEC-2021-0079.json",
                "d113c2bd1ad6c3ac00a3a8d3f89d3f38de935f8ede0d174a55afe9911960cf51",
            )
            .await?;

        assert!(loaded_advisory.is_some());

        Ok(())
    }
}
