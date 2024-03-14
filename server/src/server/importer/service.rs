use crate::server::importer::model::ImportConfiguration;
use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde_json::Value;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use trustify_common::error::ErrorInformation;
use trustify_graph::graph::Graph;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("importer '{0}' already exists")]
    AlreadyExists(String),
    #[error("importer '{0}' not found")]
    NotFound(String),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Error::AlreadyExists(name) => HttpResponse::Conflict().json(ErrorInformation {
                error: "AlreadyExists".into(),
                message: self.to_string(),
                details: None,
            }),
            Error::NotFound(name) => HttpResponse::Conflict().json(ErrorInformation {
                error: "NotFound".into(),
                message: self.to_string(),
                details: None,
            }),
        }
    }
}

static MOCK: Lazy<RwLock<BTreeMap<String, Value>>> = Lazy::new(|| RwLock::new(BTreeMap::new()));

pub struct ImporterService {
    graph: Graph,
}

impl ImporterService {
    pub fn new(graph: Graph) -> Self {
        Self { graph }
    }

    pub async fn list(&self) -> Result<Vec<ImportConfiguration>, Error> {
        Ok(MOCK
            .read()
            .iter()
            .map(|(name, configuration)| ImportConfiguration {
                name: name.clone(),
                configuration: configuration.clone(),
            })
            .collect())
    }

    pub async fn create(
        &self,
        name: String,
        configuration: Value,
    ) -> Result<ImportConfiguration, Error> {
        match MOCK.write().entry(name.clone()) {
            Entry::Vacant(mut entry) => {
                entry.insert(configuration.clone());
                Ok(ImportConfiguration {
                    name,
                    configuration,
                })
            }
            Entry::Occupied(_) => Err(Error::AlreadyExists(name)),
        }
    }

    pub async fn read(&self, name: &str) -> Result<Option<ImportConfiguration>, Error> {
        Ok(MOCK
            .read()
            .get(name)
            .map(|configuration| ImportConfiguration {
                name: name.to_string(),
                configuration: configuration.clone(),
            }))
    }

    pub async fn update(
        &self,
        name: String,
        configuration: Value,
    ) -> Result<ImportConfiguration, Error> {
        match MOCK.write().entry(name.clone()) {
            Entry::Vacant(_) => Err(Error::NotFound(name)),
            Entry::Occupied(mut entry) => {
                entry.insert(configuration.clone());
                Ok(ImportConfiguration {
                    name,
                    configuration,
                })
            }
        }
    }

    pub async fn delete(&self, name: &str) -> Result<bool, Error> {
        Ok(MOCK.write().remove(name).is_some())
    }
}
