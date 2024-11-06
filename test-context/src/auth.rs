use actix_http::{HttpMessage, Request};
use trustify_auth::authenticator::user::{UserDetails, UserInformation};

/// Convenient way of adding (authenticated) user information to the request.
pub trait TestAuthentication: Sized {
    /// Make the request an authenticated request with the provided user details
    fn test_auth_details(self, details: UserDetails) -> Self;

    /// Make the request an authenticated request with the provided user id
    fn test_auth(self, id: impl Into<String>) -> Self {
        self.test_auth_details(UserDetails {
            id: id.into(),
            permissions: vec![],
        })
    }
}

impl TestAuthentication for Request {
    fn test_auth_details(self, details: UserDetails) -> Self {
        test_auth(self, details)
    }
}

/// Add data making the request authenticated.
pub fn test_auth(request: Request, details: UserDetails) -> Request {
    request
        .extensions_mut()
        .insert(UserInformation::Authenticated(details));
    request
}
