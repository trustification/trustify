use crate::{
    graph::{sbom::clearly_defined::Curation, Graph},
    model::IngestResult,
    service::{
        advisory::{csaf::loader::CsafLoader, cve::loader::CveLoader, osv::loader::OsvLoader},
        sbom::{
            clearly_defined::ClearlyDefinedLoader, cyclonedx::CyclonedxLoader, spdx::SpdxLoader,
        },
        weakness::CweCatalogLoader,
        Error,
    },
};
use bytes::Bytes;
use csaf::Csaf;
use cve::Cve;
use cyclonedx_bom::models::bom::Bom;
use futures::{Stream, TryStreamExt};
use jsn::{mask::*, Format as JsnFormat, TokenReader};
use osv::schema::Vulnerability;
use quick_xml::{events::Event, Reader};
use serde_json::Value;
use std::{
    io::Cursor,
    io::{self},
    pin::pin,
};
use tokio::io::AsyncReadExt;
use tokio_util::io::StreamReader;
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::labels::Labels;

#[derive(Debug)]
pub enum Format {
    OSV,
    CSAF,
    CVE,
    SPDX,
    CycloneDX,
    ClearlyDefined,
    CweCatalog,
    // These should be resolved to one of the above before loading
    Advisory,
    SBOM,
    Unknown,
}

impl<'g> Format {
    #[instrument(skip(self, graph, stream))]
    pub async fn load<S>(
        &self,
        graph: &'g Graph,
        labels: Labels,
        issuer: Option<String>,
        digests: &Digests,
        stream: S,
    ) -> Result<IngestResult, Error>
    where
        S: Stream<Item = Result<Bytes, anyhow::Error>> + Send + 'static,
    {
        let mut buffer = Vec::new();
        let mut s = pin!(StreamReader::new(
            stream.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}"))),
        ));
        s.read_to_end(&mut buffer).await?;

        match self {
            Format::CSAF => {
                // issuer is internal as publisher of the document.
                let loader = CsafLoader::new(graph);
                let csaf: Csaf = serde_json::from_slice(&buffer)?;
                loader.load(labels, csaf, digests).await
            }
            Format::OSV => {
                // issuer is :shrug: sometimes we can tell, sometimes not :shrug:
                let loader = OsvLoader::new(graph);
                let osv: Vulnerability = serde_json::from_slice(&buffer)?;
                loader.load(labels, osv, digests, issuer).await
            }
            Format::CVE => {
                // issuer is always CVE Project
                let loader = CveLoader::new(graph);
                let cve: Cve = serde_json::from_slice(&buffer)?;
                loader.load(labels, cve, digests).await
            }
            Format::SPDX => {
                let loader = SpdxLoader::new(graph);
                let v: Value = serde_json::from_slice(&buffer)?;
                loader.load(labels, v, digests).await
            }
            Format::CycloneDX => {
                let loader = CyclonedxLoader::new(graph);
                let v: Value = serde_json::from_slice(&buffer)?;
                let sbom = Bom::parse_json_value(v)
                    .map_err(|err| Error::UnsupportedFormat(format!("Failed to parse: {err}")))?;

                loader.load(labels, sbom, digests).await
            }
            Format::ClearlyDefined => {
                let loader = ClearlyDefinedLoader::new(graph);
                let curation: Curation = serde_yml::from_slice(&buffer)?;
                loader.load(labels, curation, digests).await
            }
            Format::CweCatalog => {
                let loader = CweCatalogLoader::new(graph);
                loader.load_bytes(labels, &buffer, digests).await
            }
            f => Err(Error::UnsupportedFormat(format!(
                "Must resolve {f:?} to an actual format"
            ))),
        }
    }

    #[instrument(skip_all, ret)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match Self::advisory_from_bytes(bytes) {
            Err(Error::UnsupportedFormat(ea)) => match Self::sbom_from_bytes(bytes) {
                Err(Error::UnsupportedFormat(es)) => match Self::is_cwe_catalog(bytes) {
                    Ok(_) => Ok(Self::CweCatalog),
                    Err(_) => Err(Error::UnsupportedFormat(format!("{ea}\n{es}"))),
                },
                x => x,
            },
            x => x,
        }
    }

    #[instrument(skip_all, ret)]
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

    #[instrument(skip_all, ret)]
    pub fn sbom_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if Self::is_spdx(bytes)? {
            Ok(Format::SPDX)
        } else if Self::is_cyclonedx(bytes)? {
            Ok(Format::CycloneDX)
        } else if Self::is_clearly_defined(bytes)? {
            Ok(Format::ClearlyDefined)
        } else {
            Err(Error::UnsupportedFormat(
                "Unable to detect SBOM format; only SPDX and CycloneDX are supported".into(),
            ))
        }
    }

    pub fn is_csaf(bytes: &[u8]) -> Result<bool, Error> {
        match masked(
            key("document").and(key("csaf_version")).and(depth(2)),
            bytes,
        ) {
            Ok(Some(_)) => Ok(true),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_cve(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("dataType")), bytes) {
            Ok(Some(_)) => Ok(true),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_osv(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("id")), bytes) {
            Ok(Some(_)) => Ok(true),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_spdx(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("spdxVersion")), bytes) {
            Ok(Some(x)) if matches!(x.as_str(), "SPDX-2.2" | "SPDX-2.3") => Ok(true),
            Ok(Some(x)) => Err(Error::UnsupportedFormat(format!(
                "SPDX version {x} is unsupported; try 2.2 or 2.3"
            ))),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_cyclonedx(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("specVersion")), bytes) {
            Ok(Some(x)) if matches!(x.as_str(), "1.3" | "1.4" | "1.5") => Ok(true),
            Ok(Some(x)) => Err(Error::UnsupportedFormat(format!(
                "CycloneDX version {x} is unsupported; try 1.3, 1.4, or 1.5"
            ))),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_clearly_defined(bytes: &[u8]) -> Result<bool, Error> {
        // first just try to get some YAML.
        if let Ok(candidate) = serde_yml::from_slice::<'_, serde_yml::Value>(bytes) {
            // does it have a root `coordinates`?
            if candidate.get("coordinates").is_some() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn is_cwe_catalog(bytes: &[u8]) -> Result<bool, Error> {
        let xml = Cursor::new(bytes);
        let mut reader = Reader::from_reader(xml);

        let mut buf = Vec::new();
        loop {
            // read events until we find the first tag, or an error
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(event)) => {
                    // first tag will have some attributes, let's see if it matches our
                    // expected schema.
                    let attrs = event.attributes();
                    for attr in attrs.into_iter().flatten() {
                        if attr.key.local_name().into_inner() == b"schemaLocation" {
                            // The attribute value is weird, and possibly wrong with a
                            // strange prefix URL that does not resolve before the actual
                            // xsd url, hence using `ends_with(...)` to match.
                            if attr
                                .value
                                .ends_with(b"http://cwe.mitre.org/data/xsd/cwe_schema_v7.2.xsd")
                            {
                                // It's a CWE catalog, yay.
                                return Ok(true);
                            }
                        }
                    }
                    // First tag was apparently not the droids we were looking for.
                    return Ok(false);
                }
                Err(_) => return Ok(false),
                _ => {
                    // not an error or a start tag, keep on looping
                    buf.clear()
                }
            }
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
    use std::io::Read;
    use test_log::test;
    use trustify_test_context::document_bytes;
    use trustify_test_context::document_read;
    use zip::ZipArchive;

    #[test(tokio::test)]
    async fn detection() -> Result<(), anyhow::Error> {
        let csaf = document_bytes("csaf/CVE-2023-20862.json").await?;
        assert!(matches!(Format::from_bytes(&csaf), Ok(Format::CSAF)));

        let osv = document_bytes("osv/RUSTSEC-2021-0079.json").await?;
        assert!(matches!(Format::from_bytes(&osv), Ok(Format::OSV)));

        let cve = document_bytes("mitre/CVE-2024-27088.json").await?;
        assert!(matches!(Format::from_bytes(&cve), Ok(Format::CVE)));

        let cyclone = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;
        assert!(matches!(
            Format::from_bytes(&cyclone),
            Ok(Format::CycloneDX)
        ));

        let spdx = document_bytes("ubi9-9.2-755.1697625012.json").await?;
        assert!(matches!(Format::from_bytes(&spdx), Ok(Format::SPDX)));

        let cwe = document_read("cwec_latest.xml.zip").await?;
        let mut cwe = ZipArchive::new(cwe)?;
        let mut cwe = cwe.by_index(0)?;
        let mut xml = Vec::new();
        cwe.read_to_end(&mut xml)?;
        assert!(matches!(Format::from_bytes(&xml), Ok(Format::CweCatalog)));

        Ok(())
    }
}
