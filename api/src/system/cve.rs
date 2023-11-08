use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::InnerSystem;

impl InnerSystem {
    pub async fn ingest_cve(&self, identifier: &str, tx: Transactional<'_>) -> Result<CveContext, Error> {
        todo!()
    }

}

pub struct CveContext {

}