use crate::{Error, source_document::model::SourceDocument};
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, PaginatorTrait, Statement};
use trustify_module_storage::service::{StorageBackend, StorageKey, dispatch::DispatchBackend};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum DocumentType {
    Advisory,
    Sbom,
}

/// Fetch all unique key/value labels matching the `filter_text` for all the `r#type` entities, i.e. `DocumentType::Advisory` or `DocumentType::Sbom`
///
/// If limit=0 then all data will be fetched
pub async fn fetch_labels<C: ConnectionTrait>(
    r#type: DocumentType,
    filter_text: String,
    limit: u64,
    connection: &C,
) -> Result<Vec<serde_json::Value>, Error> {
    let sql = format!(
        r#"
SELECT DISTINCT ON (kv.key, kv.value)
    kv.key,
    CASE
        WHEN kv.value IS NULL OR kv.value = '' THEN NULL
        ELSE kv.value
    END AS value
FROM {table},
    LATERAL jsonb_each_text(labels) AS kv
WHERE
    CASE
        WHEN kv.value IS NULL THEN kv.key
        ELSE kv.key || '=' || kv.value
    END ILIKE $1 ESCAPE '\'
ORDER BY
    kv.key, kv.value
"#,
        table = match r#type {
            DocumentType::Advisory => "advisory",
            DocumentType::Sbom => "sbom",
        }
    );

    let statement = Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        [format!("%{}%", escape(filter_text)).into()],
    );

    let selector = serde_json::Value::find_by_statement(statement);
    let labels: Vec<serde_json::Value> = if limit == 0 {
        selector.all(connection).await?
    } else {
        selector.paginate(connection, limit).fetch().await?
    };

    Ok(labels)
}

fn escape(text: String) -> String {
    text.replace('%', "\\").replace('\\', "\\\\")
}

pub async fn delete_doc(
    doc: &Option<SourceDocument>,
    storage: impl DocumentDelete,
) -> Result<(), Error> {
    if let Some(doc) = doc {
        let k = doc.try_into()?;
        storage.delete(k).await?;
    }
    Ok(())
}
pub trait DocumentDelete {
    fn delete(&self, key: StorageKey) -> impl Future<Output = Result<(), Error>>;
}
impl DocumentDelete for &DispatchBackend {
    async fn delete(&self, key: StorageKey) -> Result<(), Error> {
        (*self).delete(key).await.map_err(Error::Storage)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::anyhow;
    use test_log::test;
    use trustify_module_storage::service::StorageKey;

    #[test(tokio::test)]
    async fn delete_failure() -> Result<(), anyhow::Error> {
        // Setup mock that simulates a delete error
        struct FailingDelete {}
        impl DocumentDelete for FailingDelete {
            async fn delete(&self, _key: StorageKey) -> Result<(), Error> {
                Err(Error::Storage(anyhow!("delete from storage failed")))
            }
        }

        // Deleting no doc is fine, error or not
        assert!(delete_doc(&None, FailingDelete {}).await.is_ok());

        // Failing to delete doc from storage should return error
        let doc = SourceDocument::default();
        assert!(delete_doc(&Some(doc), FailingDelete {}).await.is_err());

        Ok(())
    }
}
