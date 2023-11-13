use crate::system::error::Error;
use async_trait::async_trait;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, EntityTrait,
    ExecResult, FromQueryResult, ModelTrait, PaginatorTrait, QueryResult, Select, Statement,
};
use std::marker::PhantomData;
use std::process::Output;

#[derive(Copy, Clone)]
pub enum Transactional<'db> {
    None,
    Some(&'db DatabaseTransaction),
}

impl<'db> From<&'db DatabaseTransaction> for Transactional<'db> {
    fn from(inner: &'db DatabaseTransaction) -> Self {
        Self::Some(inner)
    }
}

#[derive(Clone)]
pub enum ConnectionOrTransaction<'db> {
    Connection(&'db DatabaseConnection),
    Transaction(&'db DatabaseTransaction),
}

#[async_trait::async_trait]
impl ConnectionTrait for ConnectionOrTransaction<'_> {
    fn get_database_backend(&self) -> DbBackend {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.get_database_backend(),
            ConnectionOrTransaction::Transaction(inner) => inner.get_database_backend(),
        }
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.execute(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.execute(stmt).await,
        }
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.execute_unprepared(sql).await,
            ConnectionOrTransaction::Transaction(inner) => inner.execute_unprepared(sql).await,
        }
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.query_one(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.query_one(stmt).await,
        }
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.query_all(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.query_all(stmt).await,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Paginated {
    pub page_size: u64,
    pub page: u64,
}

#[derive(Debug, Clone)]
pub struct PaginatedResults<R> {
    pub results: Vec<R>,
    pub page: u64,
    pub num_items: u64,
    pub num_pages: u64,
    pub prev_page: Option<Paginated>,
    pub next_page: Option<Paginated>,
}
