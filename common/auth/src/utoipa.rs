use std::collections::BTreeMap;
use utoipa::{
    IntoResponses,
    openapi::{RefOr, Response, ResponseBuilder, ResponsesBuilder},
};

pub enum AuthResponse {
    NotAuthenticated,
    NotAuthorized,
}

impl IntoResponses for AuthResponse {
    fn responses() -> BTreeMap<String, RefOr<Response>> {
        ResponsesBuilder::new()
            .response(
                "401",
                ResponseBuilder::new()
                    .description("The user did not provide valid authentication credentials"),
            )
            .response(
                "403",
                ResponseBuilder::new().description("The user lacks the required permission"),
            )
            .build()
            .into()
    }
}
