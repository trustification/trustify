use crate::endpoints::configure;
use actix_http::Request;
use actix_web::{
    dev::{Service, ServiceResponse},
    web, App, Error,
};
use bytes::Bytes;
use sea_orm::prelude::async_trait::async_trait;
use serde::de::DeserializeOwned;
use trustify_auth::authorizer::Authorizer;
use trustify_test_context::TrustifyContext;

/// A trait wrapping an `impl Service` in a way that we can pass it as a reference.
#[async_trait(?Send)]
pub trait CallService {
    async fn call_service(&self, s: Request) -> ServiceResponse;
    async fn call_and_read_body(&self, r: Request) -> Bytes;
    async fn call_and_read_body_json<T: DeserializeOwned>(&self, r: Request) -> T;
}

#[async_trait(?Send)]
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

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService> {
    Ok(actix_web::test::init_service(
        App::new()
            .app_data(web::PayloadConfig::default().limit(5 * 1024 * 1024))
            .app_data(web::Data::new(Authorizer::new(None)))
            .service(web::scope("/api").configure(|svc| configure(svc, ctx.db.clone()))),
    )
    .await)
}
