mod pgp;

use crate::{
    error::{Error, PatchError},
    model::{Signature, TrustAnchor, TrustAnchorData, VerificationResult},
    service::trust_anchor::pgp::Anchor,
};
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryOrder, Set, prelude::Uuid, query::QueryFilter,
};
use sea_query::{Expr, Order, SimpleExpr};
use sequoia_openpgp::{Cert, cert::CertParser, parse::Parse};
use std::time::SystemTime;
use std::{
    fmt::{Debug, Display},
    fs::File,
};
use tracing::instrument;
use trustify_common::{
    db::{Database, DatabaseErrors, limiter::LimiterTrait},
    model::{Paginated, PaginatedResults, Revisioned},
};
use trustify_entity::{signature_type::SignatureType, trust_anchor};

/// A service managing trust anchors for signatures of documents.
pub struct TrustAnchorService {
    db: Database,
}

impl TrustAnchorService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list(&self, paginated: Paginated) -> Result<PaginatedResults<TrustAnchor>, Error> {
        let query = trust_anchor::Entity::find()
            .order_by(trust_anchor::Column::Id, Order::Asc)
            .limiting(&self.db, paginated.offset, paginated.limit);

        let total = query.total().await?;
        let items = query
            .fetch()
            .await?
            .into_iter()
            .map(TrustAnchor::from)
            .collect::<_>();

        Ok(PaginatedResults { items, total })
    }

    pub async fn create(&self, id: String, trust_anchor: TrustAnchorData) -> Result<(), Error> {
        let entity = trust_anchor::ActiveModel {
            id: Set(id.clone()),
            revision: Set(Uuid::new_v4()),
            r#type: Set(trust_anchor.r#type),
            payload: Set(trust_anchor.payload),
            description: Set(trust_anchor.description),
            disabled: Set(trust_anchor.disabled),
        };

        match entity.insert(&self.db).await {
            Err(err) if err.is_duplicate() => Err(Error::AlreadyExists(id)),
            r => r.map_err(Error::from),
        }?;

        Ok(())
    }

    pub async fn read(&self, id: &str) -> Result<Option<Revisioned<TrustAnchor>>, Error> {
        let result = trust_anchor::Entity::find_by_id(id).one(&self.db).await?;

        Ok(result.map(TrustAnchor::from_revisioned))
    }

    /// Load a configuration, transform, and store it back (aka patch).
    ///
    /// The function loads the configuration, and then applies the provided transform function.
    ///
    /// If the revision of the loaded configuration does not match, an error is reported. Also,
    /// if the final update doesn't match the loaded revision, an error is reported.
    pub async fn patch_data<F, E>(
        &self,
        id: &str,
        expected_revision: Option<&str>,
        f: F,
    ) -> Result<(), PatchError<E>>
    where
        E: Debug + Display,
        F: FnOnce(TrustAnchorData) -> Result<TrustAnchorData, E>,
    {
        // fetch the current state
        let Some(current) = self.read(id).await? else {
            // not found -> don't update
            return Err(Error::NotFound(id.into()).into());
        };

        if let Some(expected) = expected_revision {
            if expected != current.revision {
                // we expected something, but found something else -> abort
                return Err(Error::MidAirCollision.into());
            }
        }

        // apply mutation

        let data = f(current.value.data).map_err(PatchError::Transform)?;

        // store

        Ok(self.update_data(id, Some(&current.revision), data).await?)
    }

    pub async fn update_data(
        &self,
        id: &str,
        expected_revision: Option<&str>,
        data: TrustAnchorData,
    ) -> Result<(), Error> {
        let TrustAnchorData {
            disabled,
            description,
            r#type,
            payload,
        } = data;

        self.update(
            &self.db,
            id,
            expected_revision,
            vec![
                (trust_anchor::Column::Type, r#type.as_enum()),
                (trust_anchor::Column::Payload, payload.into()),
                (trust_anchor::Column::Description, description.into()),
                (trust_anchor::Column::Disabled, disabled.into()),
            ],
        )
        .await
    }

    async fn update<C>(
        &self,
        db: &C,
        name: &str,
        expected_revision: Option<&str>,
        updates: Vec<(trust_anchor::Column, SimpleExpr)>,
    ) -> Result<(), Error>
    where
        C: ConnectionTrait,
    {
        let mut update = trust_anchor::Entity::update_many()
            .col_expr(trust_anchor::Column::Revision, Expr::value(Uuid::new_v4()))
            .filter(trust_anchor::Column::Id.eq(name));

        for (col, expr) in updates {
            update = update.col_expr(col, expr);
        }

        if let Some(revision) = expected_revision {
            update = update.filter(
                trust_anchor::Column::Revision
                    .into_expr()
                    .cast_as("text")
                    .eq(revision),
            );
        }

        let result = update.exec(db).await?;

        if result.rows_affected == 0 {
            // now we need to figure out if the item wasn't there or if it was modified
            if trust_anchor::Entity::find_by_id(name)
                .count(&self.db)
                .await?
                == 0
            {
                Err(Error::NotFound(name.to_string()))
            } else {
                Err(Error::MidAirCollision)
            }
        } else {
            Ok(())
        }
    }

    #[instrument(skip(self))]
    pub async fn delete(&self, id: &str, expected_revision: Option<&str>) -> Result<bool, Error> {
        let mut delete =
            trust_anchor::Entity::delete_many().filter(trust_anchor::Column::Id.eq(id));

        if let Some(revision) = expected_revision {
            delete = delete.filter(
                trust_anchor::Column::Revision
                    .into_expr()
                    .cast_as("text")
                    .eq(revision),
            );
        }

        let result = delete.exec(&self.db).await?;

        Ok(result.rows_affected > 0)
    }

    #[instrument(skip(self, signatures, content))]
    pub async fn verify(
        &self,
        signatures: Vec<Signature>,
        content: File,
    ) -> Result<Vec<VerificationResult>, Error> {
        let anchors = trust_anchor::Entity::find().all(&self.db).await?;

        let now = SystemTime::now();

        let anchors: Vec<_> = anchors
            .into_iter()
            .filter(|a| !a.disabled)
            .filter_map(|anchor| match anchor.r#type {
                SignatureType::Pgp => CertParser::from_bytes(&anchor.payload)
                    .ok()
                    .and_then(|certificates| certificates.collect::<Result<Vec<Cert>, _>>().ok())
                    .map(|certificates| {
                        (
                            TrustAnchor::from(anchor),
                            Anchor::Pgp {
                                certificates,
                                // TODO: allow specifying time for v3 signatures
                                policy_time: now,
                            },
                        )
                    }),
            })
            .collect();

        let mut result = Vec::with_capacity(signatures.len());

        for signature in signatures {
            log::trace!("Signature: {:?}", signature);

            let mut trust_anchors = vec![];

            for anchor in &anchors {
                log::trace!("  Anchor: {:?}", anchor);

                match anchor
                    .1
                    .validate(
                        &signature,
                        content.try_clone().map_err(|err| Error::Any(err.into()))?,
                    )
                    .await
                {
                    Ok(()) => {
                        // TODO: report result
                        trust_anchors.push(anchor.0.clone());
                    }
                    Err(err) => {
                        log::debug!("Failed: {err}");
                    }
                }
            }

            result.push(VerificationResult {
                signature,
                trust_anchors,
            });
        }

        Ok(result)
    }
}
