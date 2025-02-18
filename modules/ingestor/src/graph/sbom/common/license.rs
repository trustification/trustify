use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use spdx_expression::SpdxExpression;
use std::collections::{BTreeMap, HashMap};
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::license;
use uuid::Uuid;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LicenseInfo {
    pub license: String,
    pub refs: HashMap<String, String>,
}

impl LicenseInfo {
    pub fn uuid(&self) -> Uuid {
        let mut text = self.license.clone();

        for (user_ref, user_license) in &self.refs {
            if &text == user_ref {
                text = user_license.clone();
            }
        }

        // UUID based upon a hash of the lowercase de-ref'd license.
        Uuid::new_v5(&NAMESPACE, text.to_lowercase().as_bytes())
    }

    pub fn spdx_info(&self) -> (Vec<String>, Vec<String>) {
        SpdxExpression::parse(&self.license)
            .map(|parsed| {
                let spdx_licenses = parsed
                    .licenses()
                    .iter()
                    .filter(|e| !e.license_ref)
                    .map(|e| e.identifier.to_string())
                    .collect::<Vec<_>>();

                let spdx_license_exceptions = parsed
                    .exceptions()
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>();

                (spdx_licenses, spdx_license_exceptions)
            })
            .unwrap_or((vec![], vec![]))
    }
}

#[derive(Default, Debug)]
pub struct LicenseCreator {
    /// The licenses to create.
    ///
    /// Uses a [`BTreeMap`] to ensure we have a stable insertion order, avoiding deadlocks on the
    /// database.
    licenses: BTreeMap<Uuid, license::ActiveModel>,
}

impl LicenseCreator {
    pub fn new() -> Self {
        Self {
            licenses: Default::default(),
        }
    }

    pub fn add(&mut self, info: &LicenseInfo) {
        let uuid = info.uuid();

        let (spdx_licenses, spdx_exceptions) = info.spdx_info();

        self.licenses.entry(uuid).or_insert(license::ActiveModel {
            id: Set(uuid),
            text: Set(info.license.clone()),
            spdx_licenses: if spdx_licenses.is_empty() {
                Set(None)
            } else {
                Set(Some(spdx_licenses))
            },
            spdx_license_exceptions: if spdx_exceptions.is_empty() {
                Set(None)
            } else {
                Set(Some(spdx_exceptions))
            },
        });
    }

    #[instrument(skip_all, fields(num = self.licenses.len()), err(level=tracing::Level::INFO))]
    pub async fn create<'g, C>(self, db: &C) -> Result<(), DbErr>
    where
        C: ConnectionTrait,
    {
        for batch in &self.licenses.into_values().chunked() {
            license::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([license::Column::Id])
                        .do_nothing()
                        .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::graph::sbom::LicenseInfo;
    use std::collections::HashMap;

    #[test]
    fn stable_uuid() {
        // create a new license, ensure a new random state of the hashmap
        let license = || LicenseInfo {
            license: "LicenseRef-1-2-3".to_string(),
            refs: {
                let mut refs = HashMap::new();
                refs.insert("LicenseRef".to_string(), "CyberNeko License".to_string());
                refs.insert(
                    "LicenseRef-1".to_string(),
                    "CyberNeko License 1".to_string(),
                );
                refs.insert(
                    "LicenseRef-1-2".to_string(),
                    "CyberNeko License 1-2".to_string(),
                );
                refs.insert(
                    "LicenseRef-1-2-3".to_string(),
                    "CyberNeko License 1-2-3".to_string(),
                );
                refs
            },
        };

        // the original one we compare to
        let original = license();

        for _ in 0..10 {
            // a new one, containing the same information
            let new = license();
            // should be equal
            assert_eq!(original, new);
            // and generate the same UUID
            assert_eq!(original.uuid(), new.uuid());
        }
    }
}
