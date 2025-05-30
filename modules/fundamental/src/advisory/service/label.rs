use super::AdvisoryService;
use crate::{Error, advisory::model::raw_sql::SEARCH_LABELS_SQL};
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, PaginatorTrait, Statement};

impl AdvisoryService {
    // Fetch all unique key/value labels of all Advisories
    // If limit=0 then all data will be fetched
    pub async fn fetch_labels<C: ConnectionTrait>(
        &self,
        filter_text: &str,
        limit: u64,
        connection: &C,
    ) -> Result<Vec<serde_json::Value>, Error> {
        let statement = Statement::from_sql_and_values(
            DbBackend::Postgres,
            SEARCH_LABELS_SQL,
            [format!("%{}%", filter_text).into()],
        );

        let selector = serde_json::Value::find_by_statement(statement);
        let labels: Vec<serde_json::Value> = if limit == 0 {
            selector.all(connection).await?
        } else {
            selector.paginate(connection, limit).fetch().await?
        };

        Ok(labels)
    }
}
