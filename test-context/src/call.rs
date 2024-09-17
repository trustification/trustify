use actix_http::Request;
use actix_web::{
    dev::{Service, ServiceResponse},
    Error,
};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use std::future::Future;

/// A trait wrapping an `impl Service` in a way that we can pass it as a reference.
pub trait CallService {
    fn call_service(&self, s: Request) -> impl Future<Output = ServiceResponse>;
    fn call_and_read_body(&self, r: Request) -> impl Future<Output = Bytes>;
    fn call_and_read_body_json<T: DeserializeOwned>(&self, r: Request) -> impl Future<Output = T>;
}

impl<S> CallService for S
where
    S: Service<Request, Response = ServiceResponse, Error = Error>,
{
    async fn call_service(&self, r: Request) -> ServiceResponse {
        actix_web::test::call_service(self, r).await
    }

    async fn call_and_read_body(&self, r: Request) -> Bytes {
        actix_web::test::call_and_read_body(self, r).await
    }

    async fn call_and_read_body_json<T: DeserializeOwned>(&self, r: Request) -> T {
        actix_web::test::call_and_read_body_json(self, r).await
    }
}
