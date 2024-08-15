use crate::service::sbom::clearly_defined::ClearlyDefinedLoader;
use crate::{
    graph::Graph,
    model::IngestResult,
    service::{
        advisory::{csaf::loader::CsafLoader, cve::loader::CveLoader, osv::loader::OsvLoader},
        sbom::{cyclonedx::CyclonedxLoader, spdx::SpdxLoader},
        Error,
    },
};
use bytes::Bytes;
use csaf::Csaf;
use cve::Cve;
use cyclonedx_bom::models::bom::Bom;
use futures::Stream;
use futures::TryStreamExt;
use jsn::{mask::*, Format as JsnFormat, TokenReader};
use osv::schema::Vulnerability;
use serde_json::Value;
use std::{
    io::{self},
    pin::pin,
};
use tokio_util::io::{StreamReader, SyncIoBridge};
use tracing::info_span;
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
}

impl<'g> Format {
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
        match self {
            Format::CSAF => {
                // issuer is internal as publisher of the document.
                let loader = CsafLoader::new(graph);
                let csaf: Csaf = json_from_stream(stream).await?;
                loader.load(labels, csaf, digests).await
            }
            Format::OSV => {
                // issuer is :shrug: sometimes we can tell, sometimes not :shrug:
                let loader = OsvLoader::new(graph);
                let osv: Vulnerability = json_from_stream(stream).await?;
                loader.load(labels, osv, digests, issuer).await
            }
            Format::CVE => {
                // issuer is always CVE Project
                let loader = CveLoader::new(graph);
                let cve: Cve = json_from_stream(stream).await?;
                loader.load(labels, cve, digests).await
            }
            Format::SPDX => {
                let loader = SpdxLoader::new(graph);
                let v: Value = json_from_stream(stream).await?;
                loader.load(labels, v, digests).await
            }
            Format::CycloneDX => {
                let loader = CyclonedxLoader::new(graph);
                let v: Value = json_from_stream(stream).await?;
                let sbom = Bom::parse_json_value(v)
                    .map_err(|err| Error::UnsupportedFormat(format!("Failed to parse: {err}")))?;

                loader.load(labels, sbom, digests).await
            }
            Format::ClearlyDefined => {
                let loader = ClearlyDefinedLoader::new(graph);
                let v: serde_yml::Value = yaml_from_stream(stream).await?;
                loader.load(labels, v, digests).await
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
        } else if Self::is_clearly_defined(bytes)? {
            Ok(Format::ClearlyDefined)
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
        match masked(depth(1).and(key("spdxVersion")), bytes) {
            Ok(Some(x)) if matches!(x.as_str(), "SPDX-2.2" | "SPDX-2.3") => Ok(true),
            Ok(Some(x)) => Err(Error::UnsupportedFormat(format!(
                "SPDX version {x} is unsupported; try 2.2 or 2.3"
            ))),
            Ok(None) | Err(_) => Ok(false),
        }
    }

    pub fn is_cyclonedx(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("specVersion")), bytes) {
            Ok(Some(x)) if matches!(x.as_str(), "1.3" | "1.4" | "1.5") => Ok(true),
            Ok(Some(x)) => Err(Error::UnsupportedFormat(format!(
                "CycloneDX version {x} is unsupported; try 1.3, 1.4, or 1.5"
            ))),
            Ok(None) | Err(_) => Ok(false),
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

async fn json_from_stream<S, T>(stream: S) -> Result<T, Error>
where
    S: Stream<Item = Result<Bytes, anyhow::Error>> + Send + 'static,
    T: serde::de::DeserializeOwned + Send + 'static,
{
    Ok(tokio::task::spawn_blocking(move || {
        let stream = pin!(stream);
        let stream = stream.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")));
        let reader = SyncIoBridge::new(StreamReader::new(stream));
        info_span!("parse document").in_scope(|| serde_json::from_reader(reader))
    })
    .await??)
}

async fn yaml_from_stream<S, T>(stream: S) -> Result<T, Error>
where
    S: Stream<Item = Result<Bytes, anyhow::Error>> + Send + 'static,
    T: serde::de::DeserializeOwned + Send + 'static,
{
    Ok(tokio::task::spawn_blocking(move || {
        let stream = pin!(stream);
        let stream = stream.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")));
        let reader = SyncIoBridge::new(StreamReader::new(stream));
        info_span!("parse document").in_scope(|| serde_yml::from_reader(reader))
    })
    .await??)
}

#[cfg(test)]
mod test {
    use super::*;
    use test_log::test;
    use trustify_test_context::document_bytes;

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
        Ok(())
    }
}
