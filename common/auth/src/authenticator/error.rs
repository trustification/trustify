#[cfg(feature = "actix")]
use trustify_common::error::ErrorInformation;

#[derive(Debug, thiserror::Error)]
pub enum AuthenticationError {
    #[error("Authentication failed")]
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("Authorization failed")]
    Failed,
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for AuthenticationError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_http::body::BoxBody> {
        match self {
            Self::Failed => actix_web::HttpResponse::Unauthorized().json(ErrorInformation {
                error: "Unauthorized".into(),
                message: self.to_string(),
                details: None,
            }),
        }
    }
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for AuthorizationError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_http::body::BoxBody> {
        match self {
            Self::Failed => actix_web::HttpResponse::Forbidden().json(ErrorInformation {
                error: "Forbidden".into(),
                message: self.to_string(),
                details: None,
            }),
        }
    }
}
