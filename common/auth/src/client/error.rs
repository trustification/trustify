#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    OpenId(#[from] openid::error::Error),
}
