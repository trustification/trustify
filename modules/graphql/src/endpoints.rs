use actix_web::{guard, web, HttpResponse, Result};
use async_graphql::{http::GraphiQLSource, EmptyMutation, EmptySubscription, Schema};
use async_graphql_actix_web::GraphQL;
use std::sync::Arc;
use trustify_common::db;
use trustify_common::db::Database;
use trustify_module_ingestor::graph::Graph;

use crate::RootQuery;

async fn index_graphiql() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(GraphiQLSource::build().endpoint("/graphql").finish()))
}

pub fn configure(svc: &mut web::ServiceConfig, db: Database, graph: Arc<Graph>) {
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Arc<Graph>>(graph)
        .data::<Arc<db::Database>>(Arc::new(db.clone()))
        .finish();

    svc.service(
        web::resource("/graphql")
            .guard(guard::Post())
            .to(GraphQL::new(schema.clone())),
    );
}

pub fn configure_graphiql(svc: &mut web::ServiceConfig) {
    svc.service(
        web::resource("/graphql")
            .guard(guard::Get())
            .to(index_graphiql),
    );
}
