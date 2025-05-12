use crate::{Error, signature::model::Signature};
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};
use sea_query::JoinType;
use trustify_common::{
    db::limiter::LimiterTrait,
    id::{Id, TryFilterForId},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{advisory, sbom, source_document_signature};

pub struct SignatureService;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum DocumentType {
    Advisory,
    Sbom,
}

impl SignatureService {
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
}
