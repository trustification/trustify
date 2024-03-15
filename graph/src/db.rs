use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, ExecResult,
    QueryResult, Statement,
};
use sea_query::Iden;
use std::fmt::Write;

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
