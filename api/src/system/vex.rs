use crate::system::error::Error;
use huevos_entity::cve::*;
use sea_orm::{ActiveValue::Set, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryTrait};
use sea_query::OnConflict;

pub struct CveSystem<'t> {
    pub(crate) tx: &'t DatabaseTransaction,
}

impl<'t> CveSystem<'t> {
    pub async fn ingest_cve(&self, csaf: csaf::Csaf) -> Result<(), Error> {
        for vuln in csaf.vulnerabilities.into_iter().flatten() {
            let cve = match &vuln.cve {
                Some(cve) => cve,
                None => continue,
            };

            let model = ActiveModel {
                id: Set(cve.to_string()),
            };

            let upsert = Entity::insert(model)
                .on_conflict(OnConflict::column(Column::Id).do_nothing().to_owned())
                .build(self.tx.get_database_backend());
            self.tx.execute(upsert).await?;

            // for product in vuln.product_status.into_iter().flatten() {}
        }

        Ok(())
    }
}
