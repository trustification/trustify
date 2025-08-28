use crate::{Error, source_document::model::SourceDocument};
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, PaginatorTrait, Statement};
use trustify_module_storage::service::StorageBackend;

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

pub async fn delete_doc<T: StorageBackend<Error = anyhow::Error>>(
    doc: &Option<SourceDocument>,
    storage: &T,
) -> Result<(), Error> {
    if let Some(doc) = doc {
        let k = doc.try_into()?;
        storage.delete(k).await.map_err(Error::Storage)?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::anyhow;
    use bytes::Bytes;
    use futures_util::Stream;
    use test_context::futures;
    use test_log::test;
    use time::OffsetDateTime;
    use trustify_module_storage::service::{StorageBackend, StorageKey, StorageResult, StoreError};

    #[test(tokio::test)]
    async fn delete_failure() -> Result<(), anyhow::Error> {
        // Setup mock that simulates a delete error
        struct FailingStorage {}
        impl StorageBackend for FailingStorage {
            type Error = anyhow::Error;
            async fn store<S>(&self, _: S) -> Result<StorageResult, StoreError<Self::Error>> {
                unimplemented!();
            }
            async fn retrieve<'a>(
                &self,
                _: StorageKey,
            ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + 'a>, Self::Error>
            {
                Ok(Some(futures::stream::empty()))
            }
            async fn delete(&self, _key: StorageKey) -> Result<(), Self::Error> {
                Err(anyhow!("delete from storage failed"))
            }
        }

        let storage = FailingStorage {};

        let doc = SourceDocument {
            sha256: String::from(
                "sha256:488c5d97daed3613746f0c246f4a3d1b26ea52ce43d6bdd33f4219f881a00c07",
            ),
            sha384: String::new(),
            sha512: String::new(),
            size: 0,
            ingested: OffsetDateTime::now_local()?,
        };

        assert!(delete_doc(&None, &storage).await.is_ok());
        assert!(delete_doc(&Some(doc), &storage).await.is_err());

        Ok(())
    }
}
