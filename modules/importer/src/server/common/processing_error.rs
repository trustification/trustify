use std::fmt::Debug;

#[derive(Debug, thiserror::Error)]
pub enum ProcessingError {
    #[error("critical error: {0}")]
    Critical(anyhow::Error),
    #[error("operation canceled")]
    Canceled,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
}
