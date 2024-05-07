use super::cve::cve_record::v5::CveRecord;
use super::cve::loader::CveLoader;
use crate::graph::Graph;
use crate::service::advisory::osv::schema::Vulnerability;
use crate::service::advisory::{csaf::loader::CsafLoader, osv::loader::OsvLoader};
use crate::service::Error;
use ::csaf::Csaf;
use bytes::Bytes;
use ring::digest;
use std::io::Read;
pub mod csaf;
pub mod osv;

pub enum Format {
    OSV { checksum: String },
    CSAF { checksum: String },
    CVE { checksum: String },
}

impl<'g> Format {
    pub async fn load<R: Read>(
        &self,
        graph: &'g Graph,
        source: &str,
        reader: R,
    ) -> Result<String, Error> {
        match self {
            Format::CSAF { ref checksum } => {
                let loader = CsafLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
            Format::OSV { ref checksum } => {
                let loader = OsvLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
            Format::CVE { ref checksum } => {
                let loader = CveLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
        }
    }
    pub fn from_bytes(bytes: &Bytes) -> Result<Self, Error> {
        let checksum = checksum(bytes);
        if serde_json::from_slice::<Vulnerability>(bytes).is_ok() {
            Ok(Format::OSV { checksum })
        } else if serde_json::from_slice::<Csaf>(bytes).is_ok() {
            Ok(Format::CSAF { checksum })
        } else if serde_json::from_slice::<CveRecord>(bytes).is_ok() {
            Ok(Format::CVE { checksum })
        } else {
            Err(Error::UnsupportedFormat("unknown".into()))
        }
    }
}
fn checksum(bytes: &Bytes) -> String {
    hex::encode(digest::digest(&digest::SHA256, bytes))
}
