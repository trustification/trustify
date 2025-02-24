use super::Authenticator;
use super::user::UserInformation;
use actix_http::HttpMessage;
use actix_web::dev::ServiceRequest;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use std::sync::Arc;

pub async fn openid_validator(
    req: ServiceRequest,
    auth: BearerAuth,
    authenticator: Arc<Authenticator>,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    match authenticator.validate_token(auth.token()).await {
        Ok(payload) => {
            req.extensions_mut()
                .insert(UserInformation::Authenticated(payload.into()));
            Ok(req)
        }

        Err(err) => {
            log::debug!("Failed to validate token: {err}");
            Err((err.into(), req))
        }
    }
}
