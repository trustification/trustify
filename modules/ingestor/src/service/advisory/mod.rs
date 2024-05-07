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

#[allow(clippy::large_enum_variant)]
pub enum Format {
    OSV(Vulnerability, String),
    CSAF(Csaf, String),
    CVE(CveRecord, String),
}

impl<'g> Format {
    pub async fn load<R: Read>(
        &self,
        graph: &'g Graph,
        source: &str,
        reader: R,
    ) -> Result<String, Error> {
        match self {
            Format::CSAF(_, ref checksum) => {
                let loader = CsafLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
            Format::OSV(_, ref checksum) => {
                let loader = OsvLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
            Format::CVE(_, ref checksum) => {
                let loader = CveLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
        }
    }
    pub fn from_bytes(bytes: &Bytes) -> Result<Self, Error> {
        if let Ok(v) = serde_json::from_slice::<Vulnerability>(bytes) {
            Ok(Format::OSV(v, checksum(bytes)))
        } else if let Ok(v) = serde_json::from_slice::<Csaf>(bytes) {
            Ok(Format::CSAF(v, checksum(bytes)))
        } else if let Ok(v) = serde_json::from_slice::<CveRecord>(bytes) {
            Ok(Format::CVE(v, checksum(bytes)))
        } else {
            Err(Error::UnsupportedFormat("unknown".into()))
        }
    }
}
fn checksum(bytes: &Bytes) -> String {
    hex::encode(digest::digest(&digest::SHA256, bytes))
}
