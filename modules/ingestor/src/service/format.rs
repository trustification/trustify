use super::cve::loader::CveLoader;
use crate::graph::Graph;
use crate::service::advisory::{csaf::loader::CsafLoader, osv::loader::OsvLoader};
use crate::service::Error;
use jsn::{mask::*, Format as JsnFormat, TokenReader};
use ring::digest;
use std::io::Read;

pub enum Format {
    OSV {
        /// SHA256 digest
        checksum: String,
    },
    CSAF {
        /// SHA256 digest
        checksum: String,
    },
    CVE {
        /// SHA256 digest
        checksum: String,
    },
}

impl<'g> Format {
    pub async fn load<R: Read>(
        &self,
        graph: &'g Graph,
        source: &str,
        issuer: Option<String>,
        reader: R,
    ) -> Result<String, Error> {
        match self {
            Format::CSAF { ref checksum } => {
                // issuer is internal as publisher of the document.
                let loader = CsafLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
            Format::OSV { ref checksum } => {
                // issuer is :shrug: sometimes we can tell, sometimes not :shrug:
                let loader = OsvLoader::new(graph);
                loader.load(source, issuer, reader, checksum).await
            }
            Format::CVE { ref checksum } => {
                // issuer is always CVE Project
                let loader = CveLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let checksum = checksum(bytes);

        if masked(
            key("document").and(key("csaf_version")).and(depth(2)),
            bytes,
        ) {
            Ok(Format::CSAF { checksum })
        } else if masked(depth(1).and(key("dataType")), bytes) {
            Ok(Format::CVE { checksum })
        } else if masked(depth(1).and(key("id")), bytes) {
            Ok(Format::OSV { checksum })
        } else {
            Err(Error::UnsupportedFormat("No recognized fields".into()))
        }
    }
}

fn checksum(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, bytes))
}

fn masked<N: Mask>(mask: N, bytes: &[u8]) -> bool {
    let mut iter = TokenReader::new(bytes)
        .with_mask(mask)
        .with_format(JsnFormat::Concatenated)
        .into_iter();

    iter.next().is_some()
}

#[cfg(test)]
mod test {
    use super::*;
    use test_log::test;

    #[test(tokio::test)]
    async fn detection() -> Result<(), anyhow::Error> {
        let csaf = include_bytes!("../../../../etc/test-data/csaf/CVE-2023-20862.json");
        assert!(matches!(Format::from_bytes(csaf), Ok(Format::CSAF { .. })));
        let osv = include_bytes!("../../../../etc/test-data/osv/RUSTSEC-2021-0079.json");
        assert!(matches!(Format::from_bytes(osv), Ok(Format::OSV { .. })));
        let cve = include_bytes!("../../../../etc/test-data/mitre/CVE-2024-27088.json");
        assert!(matches!(Format::from_bytes(cve), Ok(Format::CVE { .. })));
        Ok(())
    }
}
