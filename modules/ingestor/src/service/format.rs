use crate::{
    graph::Graph,
    model::IngestResult,
    service::{
        advisory::{csaf::loader::CsafLoader, cve::loader::CveLoader, osv::loader::OsvLoader},
        sbom::{cyclonedx::CyclonedxLoader, spdx::SpdxLoader},
        Error,
    },
};
use jsn::{mask::*, Format as JsnFormat, TokenReader};
use std::io::Read;
use trustify_common::hashing::Digests;
use trustify_entity::labels::Labels;

#[derive(Debug)]
pub enum Format {
    OSV,
    CSAF,
    CVE,
    SPDX,
    CycloneDX,
}

impl<'g> Format {
    pub async fn load<R: Read>(
        &self,
        graph: &'g Graph,
        labels: Labels,
        issuer: Option<String>,
        digests: &Digests,
        reader: R,
    ) -> Result<IngestResult, Error> {
        match self {
            Format::CSAF => {
                // issuer is internal as publisher of the document.
                let loader = CsafLoader::new(graph);
                loader.load(labels, reader, digests).await
            }
            Format::OSV => {
                // issuer is :shrug: sometimes we can tell, sometimes not :shrug:
                let loader = OsvLoader::new(graph);
                loader.load(labels, reader, digests, issuer).await
            }
            Format::CVE => {
                // issuer is always CVE Project
                let loader = CveLoader::new(graph);
                loader.load(labels, reader, digests).await
            }
            Format::SPDX => {
                let loader = SpdxLoader::new(graph);
                loader.load(labels, reader, digests).await
            }
            Format::CycloneDX => {
                let loader = CyclonedxLoader::new(graph);
                loader.load(labels, reader, digests).await
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match Self::advisory_from_bytes(bytes) {
            Err(Error::UnsupportedFormat(ea)) => match Self::sbom_from_bytes(bytes) {
                Err(Error::UnsupportedFormat(es)) => {
                    Err(Error::UnsupportedFormat(format!("{ea}\n{es}")))
                }
                x => x,
            },
            x => x,
        }
    }

    pub fn advisory_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if Self::is_csaf(bytes)? {
            Ok(Format::CSAF)
        } else if Self::is_cve(bytes)? {
            Ok(Format::CVE)
        } else if Self::is_osv(bytes)? {
            Ok(Format::OSV)
        } else {
            Err(Error::UnsupportedFormat(
                "Unable to detect advisory format; only CSAF, CVE, and OSV are supported".into(),
            ))
        }
    }

    pub fn sbom_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if Self::is_spdx(bytes)? {
            Ok(Format::SPDX)
        } else if Self::is_cyclonedx(bytes)? {
            Ok(Format::CycloneDX)
        } else {
            Err(Error::UnsupportedFormat(
                "Unable to detect SBOM format; only SPDX and CycloneDX are supported".into(),
            ))
        }
    }

    pub fn is_csaf(bytes: &[u8]) -> Result<bool, Error> {
        Ok(masked(
            key("document").and(key("csaf_version")).and(depth(2)),
            bytes,
        )?
        .is_some())
    }

    pub fn is_cve(bytes: &[u8]) -> Result<bool, Error> {
        Ok(masked(depth(1).and(key("dataType")), bytes)?.is_some())
    }

    pub fn is_osv(bytes: &[u8]) -> Result<bool, Error> {
        Ok(masked(depth(1).and(key("id")), bytes)?.is_some())
    }

    pub fn is_spdx(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("spdxVersion")), bytes)? {
            Some(x) if matches!(x.as_str(), "SPDX-2.2" | "SPDX-2.3") => Ok(true),
            Some(x) => Err(Error::UnsupportedFormat(format!(
                "SPDX version {x} is unsupported; try 2.2 or 2.3"
            ))),
            None => Ok(false),
        }
    }

    pub fn is_cyclonedx(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("specVersion")), bytes)? {
            Some(x) if matches!(x.as_str(), "1.3" | "1.4" | "1.5") => Ok(true),
            Some(x) => Err(Error::UnsupportedFormat(format!(
                "CycloneDX version {x} is unsupported; try 1.3, 1.4, or 1.5"
            ))),
            None => Ok(false),
        }
    }
}

fn masked<N: Mask>(mask: N, bytes: &[u8]) -> Result<Option<String>, Error> {
    let mut iter = TokenReader::new(bytes)
        .with_mask(mask)
        .with_format(JsnFormat::Concatenated)
        .into_iter();

    iter.next()
        .map(|x| {
            x.map(|y| y.get::<String>().unwrap_or_default())
                .map_err(|e| Error::Generic(e.into()))
        })
        .transpose()
}

#[cfg(test)]
mod test {
    use super::*;
    use test_log::test;

    #[test(tokio::test)]
    async fn detection() -> Result<(), anyhow::Error> {
        let csaf = include_bytes!("../../../../etc/test-data/csaf/CVE-2023-20862.json");
        assert!(matches!(Format::from_bytes(csaf), Ok(Format::CSAF)));
        let osv = include_bytes!("../../../../etc/test-data/osv/RUSTSEC-2021-0079.json");
        assert!(matches!(Format::from_bytes(osv), Ok(Format::OSV)));
        let cve = include_bytes!("../../../../etc/test-data/mitre/CVE-2024-27088.json");
        assert!(matches!(Format::from_bytes(cve), Ok(Format::CVE)));
        let cyclone = include_bytes!("../../../../etc/test-data/zookeeper-3.9.2-cyclonedx.json");
        assert!(matches!(Format::from_bytes(cyclone), Ok(Format::CycloneDX)));
        let spdx = include_bytes!("../../../../etc/test-data/ubi9-9.2-755.1697625012.json");
        assert!(matches!(Format::from_bytes(spdx), Ok(Format::SPDX)));
        Ok(())
    }
}
