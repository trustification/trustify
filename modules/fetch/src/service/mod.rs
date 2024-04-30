pub mod advisory;
pub mod assertion;
pub mod sbom;
pub mod vulnerability;

use trustify_common::db::Database;

pub struct FetchService {
    db: Database,
}

impl FetchService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}
