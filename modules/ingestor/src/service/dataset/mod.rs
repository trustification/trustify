//! Loader for a full dataset (archive) file

use crate::{
    graph::Graph,
    model::IngestResult,
    service::{Document, Error, Format, Metadata, Signature, Warnings},
};
use anyhow::anyhow;
use bytes::Bytes;
use sbom_walker::common::compression::{self, DecompressionOptions, Detector};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    str::FromStr,
};
use tokio::runtime::Handle;
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::{labels::Labels, signature_type::SignatureType};
use trustify_module_storage::{service::StorageBackend, service::dispatch::DispatchBackend};

pub struct DatasetLoader<'g> {
    graph: &'g Graph,
    storage: &'g DispatchBackend,
    limit: usize,
}

impl<'g> DatasetLoader<'g> {
    pub fn new(graph: &'g Graph, storage: &'g DispatchBackend, limit: usize) -> Self {
        Self {
            graph,
            storage,
            limit,
        }
    }

    #[instrument(skip(self, buffer), err(level=tracing::Level::INFO))]
    pub async fn load(&self, labels: Labels, buffer: &[u8]) -> Result<DatasetIngestResult, Error> {
        let warnings = Warnings::default();
        let mut results = BTreeMap::new();

        let mut zip = zip::ZipArchive::new(Cursor::new(buffer))?;

        for i in 0..zip.len() {
            let mut file = zip.by_index(i)?;

            log::debug!("archive entry: {}", file.name());

            if !file.is_file() {
                continue;
            }
            if file.name() == ".DS_Store"
                || file.name().ends_with("/.DS_Store")
                || file.name().ends_with(".asc")
            {
                continue;
            }

            let Some(name) = file.enclosed_name() else {
                continue;
            };

            if let [loader, _path @ .., file_name] = name
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect::<Vec<_>>()
                .as_slice()
            {
                let full_name = name.display().to_string();

                log::debug!(
                    "Processing entry - loader: {loader}, path: {_path:?}, name: {file_name}"
                );
                match Format::from_str(loader) {
                    Err(_err) => {
                        warnings.add(format!("Unknown dataset file type: {loader}"));
                    }
                    Ok(format) => {
                        let mut data = Vec::with_capacity(file.size() as _);
                        file.read_to_end(&mut data)?;
                        drop(file);

                        let file_name = file_name.to_string();
                        let opts = DecompressionOptions::new().limit(self.limit);
                        let data = Handle::current()
                            .spawn_blocking(move || {
                                let detector = Detector {
                                    file_name: Some(&file_name),
                                    ..Detector::default()
                                };
                                detector
                                    .decompress_with(Bytes::from(data), &opts)
                                    .map_err(|err| match err {
                                        compression::Error::Io(err)
                                            if err.kind() == std::io::ErrorKind::WriteZero =>
                                        {
                                            Error::PayloadTooLarge
                                        }
                                        _ => Error::Generic(anyhow!("{err}")),
                                    })
                            })
                            .await??;

                        let labels = labels.clone().add("datasetFile", &full_name);

                        // find a signature

                        let signature = format!("{full_name}.asc");
                        log::debug!("Checking for a signature: {signature}");

                        let signature = match zip.by_name(&signature) {
                            Ok(mut sig) => {
                                let mut payload = Vec::with_capacity(sig.size() as _);
                                sig.read_to_end(&mut payload)?;
                                drop(sig);

                                if log::log_enabled!(log::Level::Debug) {
                                    log::debug!(
                                        "Found signature: {:?}",
                                        String::from_utf8_lossy(&payload)
                                    );
                                }

                                Some(Signature {
                                    payload,
                                    r#type: SignatureType::Pgp,
                                })
                            }
                            Err(_) => None,
                        };

                        self.storage
                            .store(&*data)
                            .await
                            .map_err(|err| Error::Storage(anyhow!("{err}")))?;

                        // We need to box it, to work around async recursion limits
                        let result = Box::pin({
                            async move {
                                format
                                    .load(
                                        self.graph,
                                        Document {
                                            metadata: Metadata {
                                                labels,
                                                issuer: None,
                                                digests: Digests::digest(&data),
                                                signatures: Vec::from_iter(signature),
                                            },
                                            data: &data,
                                        },
                                    )
                                    .await
                            }
                        })
                        .await;

                        match result {
                            Ok(result) => {
                                results.insert(full_name, result);
                            }
                            Err(err) => {
                                warnings.add(format!(
                                    "Error loading dataset file ({full_name}): {err}"
                                ));
                            }
                        }
                    }
                }
            } else {
                warnings.add(format!(
                    "Unknown dataset file name structure: {}",
                    name.display()
                ));
            }
        }

        Ok(DatasetIngestResult {
            files: results,
            warnings: warnings.into(),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct DatasetIngestResult {
    pub warnings: Vec<String>,
    pub files: BTreeMap<String, IngestResult>,
}
