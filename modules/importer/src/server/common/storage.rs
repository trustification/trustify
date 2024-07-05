use trustify_module_ingestor::service::Error;

#[derive(Debug, thiserror::Error)]
pub enum StorageError<VE> {
    #[error(transparent)]
    Validation(#[from] VE),
    #[error(transparent)]
    Processing(anyhow::Error),
    #[error(transparent)]
    Storage(Error),
    #[error("operation canceled")]
    Canceled,
}
