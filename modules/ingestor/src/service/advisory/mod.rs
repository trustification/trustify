use crate::service::advisory::{csaf::loader::CsafLoader, osv::loader::OsvLoader};
use crate::service::Error;
use std::io::Read;
use std::str::FromStr;
use crate::graph::Graph;

pub mod csaf;
pub mod osv;

pub enum Format {
    OSV,
    CSAF,
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "osv" => Ok(Self::OSV),
            "csaf" => Ok(Self::CSAF),
            _ => Err(Error::UnsupportedFormat(s.into())),
        }
    }
}

impl<'g> Format {
    pub async fn load<R: Read>(
        &self,
        graph: &'g Graph,
        source: &str,
        reader: R,
        checksum: &str,
    ) -> Result<String, Error> {
        match self {
            Format::CSAF => {
                let loader = CsafLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
            Format::OSV => {
                let loader = OsvLoader::new(graph);
                loader.load(source, reader, checksum).await
            }
        }
    }
}
