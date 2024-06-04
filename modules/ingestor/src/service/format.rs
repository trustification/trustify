use super::cve::loader::CveLoader;
use crate::graph::Graph;
use crate::service::advisory::{csaf::loader::CsafLoader, osv::loader::OsvLoader};
use crate::service::Error;
use ::csaf::Csaf;
use cve::Cve;
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

        let mut potential_errors = Vec::new();

        match serde_json::from_slice::<osv::schema::Vulnerability>(bytes) {
            Ok(_) => return Ok(Format::OSV { checksum }),
            Err(e) => {
                potential_errors.push(format!("if osv: {}", e));
            }
        }

        match serde_json::from_slice::<Csaf>(bytes) {
            Ok(_) => return Ok(Format::CSAF { checksum }),
            Err(e) => {
                potential_errors.push(format!("if csaf: {}", e));
            }
        }

        match serde_json::from_slice::<Cve>(bytes) {
            Ok(_) => return Ok(Format::CVE { checksum }),
            Err(e) => {
                potential_errors.push(format!("if cve: {}", e));
            }
        }

        Err(Error::UnsupportedFormat(format!(
            "unknown :: {:?}",
            potential_errors
        )))
    }
}

fn checksum(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, bytes))
}
