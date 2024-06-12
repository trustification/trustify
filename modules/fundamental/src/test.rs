use actix_http::Request;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::Error;
use sea_orm::prelude::async_trait::async_trait;

/// A trait wrapping an `impl Service` in a way that we can pass it as a reference.
#[async_trait(?Send)]
pub trait CallService {
    async fn call_service(&self, s: Request) -> ServiceResponse;
}

#[async_trait(?Send)]
impl<S> CallService for S
where
    S: Service<Request, Response = ServiceResponse, Error = Error>,
{
    async fn call_service(&self, r: Request) -> ServiceResponse {
        actix_web::test::call_service(self, r).await
    }
}
