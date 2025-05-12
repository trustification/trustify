use super::Graph;
use crate::{graph::error::Error, service::Signature};
use sea_orm::{ConnectionTrait, EntityTrait, Set};
use trustify_entity::source_document_signature;
use uuid::Uuid;

impl Graph {
    pub async fn attach_signatures<C: ConnectionTrait>(
        &self,
        source_document_id: Uuid,
        signatures: Vec<Signature>,
        tx: &C,
    ) -> Result<(), Error> {
        if signatures.is_empty() {
            return Ok(());
        }

        let signatures =
            signatures
                .into_iter()
                .map(|signature| source_document_signature::ActiveModel {
                    id: Set(Uuid::now_v7()),
                    document_id: Set(source_document_id),
                    r#type: Set(signature.r#type),
                    payload: Set(signature.payload),
                });

        source_document_signature::Entity::insert_many(signatures)
            .exec(tx)
            .await?;

        Ok(())
    }
}
