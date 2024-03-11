use crate::system::error::Error;
use async_trait::async_trait;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, EntityTrait,
    ExecResult, FromQueryResult, ModelTrait, PaginatorTrait, QueryResult, Select, Statement,
};
use sea_query::Iden;
use serde::Deserialize;
use std::fmt::Write;
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

#[derive(Debug, Copy, Clone, PartialEq, Deserialize)]
pub struct Paginated {
    pub page_size: u64,
    pub page: u64,
}

impl Default for Paginated {
    fn default() -> Self {
        Paginated {
            page: 1,
            page_size: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PaginatedResults<R> {
    pub results: Vec<R>,
    pub num_items: u64,
}

pub struct QualifiedPackageTransitive;

impl Iden for QualifiedPackageTransitive {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "qualified_package_transitive").unwrap();
    }
}

pub struct LeftPackageId;
impl Iden for LeftPackageId {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "left_package_id").unwrap();
    }
}
