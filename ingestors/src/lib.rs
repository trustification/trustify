pub mod advisory;
pub mod cve;
pub mod hashing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Json(serde_json::Error),
    #[error(transparent)]
    Graph(trustify_graph::graph::error::Error),
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<trustify_graph::graph::error::Error> for Error {
    fn from(value: trustify_graph::graph::error::Error) -> Self {
        Self::Graph(value)
    }
}
