pub mod csaf;
pub mod osv;

use super::Error;
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use trustify_common::db::Transactional;
use trustify_module_storage::service::StorageBackend;

impl super::IngestorService {
    pub async fn retrieve_advisory(
        &self,
        id: i32,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Error>>>, Error> {
        let Some(advisory) = self
            .graph
            .get_advisory_by_id(id, Transactional::None)
            .await?
        else {
            return Ok(None);
        };

        let hash = advisory.advisory.sha256;

        let stream = self
            .storage
            .clone()
            .retrieve(hash)
            .await
            .map_err(Error::Storage)?;

        Ok(stream.map(|stream| stream.map_err(Error::Storage)))
    }
}
