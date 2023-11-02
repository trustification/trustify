use crate::system::error::Error;
use sea_orm::DatabaseTransaction;
use std::sync::Arc;

pub struct VexSystem<'t> {
    pub(crate) tx: &'t DatabaseTransaction,
}

impl<'t> VexSystem<'t> {
    pub async fn ingest_vex(&self, vex: csaf::Csaf) -> Result<(), Error> {
        Ok(())
    }
}
