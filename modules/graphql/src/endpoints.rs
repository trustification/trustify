use crate::RootQuery;
use actix_web::{guard, web, HttpResponse, Result};
use async_graphql::{http::GraphiQLSource, EmptyMutation, EmptySubscription, Schema};
use async_graphql_actix_web::GraphQL;
use std::sync::Arc;
use trustify_common::db::Database;
use trustify_module_ingestor::graph::Graph;

async fn index_graphiql() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(GraphiQLSource::build().endpoint("/graphql").finish()))
}

pub fn configure(svc: &mut web::ServiceConfig, db: Database) {
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Arc<Graph>>(Arc::new(Graph::new(db.clone())))
        .data::<Arc<Database>>(Arc::new(db.clone()))
        .finish();

    svc.service(
        web::resource("/")
            .guard(guard::Post())
            .to(GraphQL::new(schema)),
    );
}

pub fn configure_graphiql(svc: &mut web::ServiceConfig) {
    svc.service(web::resource("/").guard(guard::Get()).to(index_graphiql));
}
