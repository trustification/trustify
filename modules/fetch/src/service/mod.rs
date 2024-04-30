mod sbom;

use trustify_common::db::Database;

pub mod advisory;
pub mod assertion;
pub mod vulnerability;

pub struct FetchService {
    db: Database,
}

impl FetchService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

