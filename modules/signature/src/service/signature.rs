use crate::{
    error::Error,
    model::{Signature, VerificationResult},
    service::{DocumentType, TrustAnchorService},
};
use futures_util::TryStreamExt;
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};
use sea_query::JoinType;
use std::pin::pin;
use tokio_util::io::StreamReader;
use trustify_common::{
    db::limiter::LimiterTrait,
    id::{Id, TryFilterForId},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{advisory, sbom, source_document_signature};
use trustify_module_storage::service::StorageBackend;

#[derive(Default)]
pub struct SignatureService;

impl SignatureService {
    pub fn new() -> Self {
        Self
    }

    /// List all signatures for a document
    pub async fn list_signatures<C: ConnectionTrait>(
        &self,
        document_type: DocumentType,
        id: Id,
        paginated: Paginated,
        db: &C,
    ) -> Result<PaginatedResults<Signature>, Error> {
        let query = source_document_signature::Entity::find();

        let query = match document_type {
            DocumentType::Advisory => query
                .join(
                    JoinType::LeftJoin,
                    source_document_signature::Entity::belongs_to(advisory::Entity)
                        .from(source_document_signature::Column::DocumentId)
                        .to(advisory::Column::SourceDocumentId)
                        .into(),
                )
                .filter(advisory::Entity::try_filter(id)?),
            DocumentType::Sbom => query
                .join(
                    JoinType::LeftJoin,
                    source_document_signature::Entity::belongs_to(sbom::Entity)
                        .from(source_document_signature::Column::DocumentId)
                        .to(sbom::Column::SourceDocumentId)
                        .into(),
                )
                .filter(sbom::Entity::try_filter(id)?),
        };

        let query = query.limiting(db, paginated.offset, paginated.limit);
        let total = query.total().await?;
        let items = query.fetch().await?;

        Ok(PaginatedResults { items, total }.map(Signature::from))
    }

    pub async fn verify<C, S>(
        &self,
        document_type: DocumentType,
        id: Id,
        paginated: Paginated,
        trust_anchor_service: &TrustAnchorService,
        db: &C,
        storage: &S,
    ) -> Result<Option<PaginatedResults<VerificationResult>>, Error>
    where
        C: ConnectionTrait,
        S: StorageBackend,
        S::Error: Into<anyhow::Error> + Send + Sync,
    {
        // look up document by id
        let Some(doc) = document_type.find_source_document(id.clone(), db).await? else {
            return Ok(None);
        };

        // fetch signatures of the document
        let result = self
            .list_signatures(document_type, id.clone(), paginated, db)
            .await?;

        if result.items.is_empty() {
            // early exit, so we don't need to fetch content or trust anchors.
            return Ok(Some(Default::default()));
        }

        let stream = storage
            .retrieve(doc.into())
            .await
            .map_err(|err| Error::Storage(err.into()))?;

        let Some(stream) = stream else {
            return Ok(None);
        };

        let content = tempfile::tempfile()?;
        let mut reader =
            pin!(StreamReader::new(stream.map_err(|err| {
                std::io::Error::other(err.into().to_string())
            })));
        tokio::io::copy(
            &mut reader,
            &mut tokio::fs::File::from_std(
                content.try_clone().map_err(|err| Error::Any(err.into()))?,
            ),
        )
        .await
        .map_err(|err| Error::Any(err.into()))?;

        Ok(Some(PaginatedResults {
            items: trust_anchor_service.verify(result.items, content).await?,
            total: result.total,
        }))
    }
}
