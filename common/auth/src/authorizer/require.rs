use crate::{
    authenticator::{error::AuthorizationError, user::UserInformation},
    authorizer::Authorizer,
};
use std::marker::PhantomData;

pub struct Require<T: Requirement>(PhantomData<T>);

#[derive(Debug, thiserror::Error)]
pub enum RequirementError {
    #[error("missing authorizer, must call .app_data(authorizer)")]
    MissingAuthorizer,
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
}

#[cfg(feature = "actix-web")]
impl actix_web::ResponseError for RequirementError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_http::body::BoxBody> {
        match self {
            Self::MissingAuthorizer => actix_web::HttpResponse::Forbidden().json(
                trustify_common::error::ErrorInformation {
                    error: "MissingAuthorizer".into(),
                    message: self.to_string(),
                    details: None,
                },
            ),
            Self::Authorization(err) => err.error_response(),
        }
    }
}

pub trait Requirement {
    fn enforce(authorizer: &Authorizer, user: &UserInformation) -> Result<(), RequirementError>;
}

#[cfg(feature = "actix-web")]
impl<T: Requirement> actix_web::FromRequest for Require<T> {
    type Error = RequirementError;
    type Future = core::future::Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_http::Payload,
    ) -> Self::Future {
        fn enforce<T: Requirement>(
            req: &actix_web::HttpRequest,
        ) -> Result<Require<T>, RequirementError> {
            use actix_http::HttpMessage;

            let authorizer = req
                .app_data::<actix_web::web::Data<Authorizer>>()
                .ok_or(RequirementError::MissingAuthorizer)?;
            let ext = req.extensions();
            let user = ext.get::<UserInformation>();

            T::enforce(authorizer, user.unwrap_or(&UserInformation::Anonymous))?;

            Ok(Require(Default::default()))
        }

        core::future::ready(enforce(req))
    }
}

#[macro_export]
macro_rules! all {
    ($n:ident -> $($r:ident),*) => {
        pub struct $n;

        impl $crate::authorizer::Requirement for $n {
            #[allow(unused)]
            fn enforce(
                authorizer: &$crate::authorizer::Authorizer,
                user: &$crate::authenticator::user::UserInformation,
            ) -> Result<(), $crate::authorizer::RequirementError> {
                $(
                    $r::enforce(authorizer, user)?;
                )*
                Ok(())
            }
        }
    };
}
