use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use spdx_expression::SpdxExpression;
use std::collections::BTreeMap;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{license, licensing_infos};
use uuid::Uuid;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LicenseInfo {
    pub license: String,
}

impl LicenseInfo {
    pub fn uuid(&self) -> Uuid {
        // UUID based upon a hash of the lowercase de-ref'd license.
        Uuid::new_v5(&NAMESPACE, self.license.to_lowercase().as_bytes())
    }

    pub fn spdx_info(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
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

                let custom_license_refs = parsed
                    .licenses()
                    .iter()
                    // There are two types of custom licenses:
                    // 1 Ones that are defined within the current SBOM, for example those with the "LicenseRef" prefix.
                    // 2 Ones that reference other SBOM documents, for example those with the "DocumentRef" prefix.
                    // We only process custom licenses that are defined in the current document.
                    .filter(|e| e.license_ref && e.document_ref.is_none())
                    .map(|e| format!("LicenseRef-{}", e.identifier))
                    .collect::<Vec<_>>();

                (spdx_licenses, spdx_license_exceptions, custom_license_refs)
            })
            .unwrap_or((vec![], vec![], vec![]))
    }
}

#[derive(Default, Debug, Clone)]
pub struct LicenseCreator {
    /// The licenses to create.
    ///
    /// Uses a [`BTreeMap`] to ensure we have a stable insertion order, avoiding deadlocks on the
    /// database.
    pub licenses: BTreeMap<Uuid, license::ActiveModel>,

    pub custom_license_list: Vec<licensing_infos::ActiveModel>,
}

impl LicenseCreator {
    pub fn new() -> Self {
        Self {
            licenses: Default::default(),
            custom_license_list: vec![],
        }
    }

    pub fn put_custom_license_list(
        &mut self,
        custom_license_list: Vec<licensing_infos::ActiveModel>,
    ) {
        self.custom_license_list = custom_license_list;
    }

    pub fn add(&mut self, info: &LicenseInfo) {
        let uuid = info.uuid();

        let (spdx_licenses, spdx_exceptions, custom_license_refs) = info.spdx_info();
        let missing_custom_refs: Vec<_> = custom_license_refs
            .iter()
            .filter(|ref_id| {
                !self
                    .custom_license_list
                    .iter()
                    .any(|c| c.license_id == Set((*ref_id).to_string()))
            })
            .cloned()
            .collect();
        if !missing_custom_refs.is_empty() {
            log::warn!(
                "The following custom license refs are missing from custom_license_list: {:?}",
                missing_custom_refs
            );
        }
        let custom_license_refs_value = if custom_license_refs.is_empty() {
            None
        } else {
            Some(self.construct_custom_license(custom_license_refs.clone()))
        };

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
            custom_license_refs: Set(custom_license_refs_value),
        });
    }

    fn construct_custom_license(&self, custom_license_ids: Vec<String>) -> Vec<String> {
        use std::collections::HashMap;
        // Build a HashMap from license_id to name for fast lookup
        let license_map: HashMap<&String, &String> = self
            .custom_license_list
            .iter()
            .filter_map(|c| {
                if let (Set(license_id), Set(name)) = (&c.license_id, &c.name) {
                    Some((license_id, name))
                } else {
                    None
                }
            })
            .collect();
        custom_license_ids
            .into_iter()
            .filter_map(|id| license_map.get(&id).map(|name| format!("{}:{}", id, name)))
            .collect()
    }

    #[instrument(skip_all, fields(num = self.licenses.len()), err(level=tracing::Level::INFO))]
    pub async fn create<C>(self, db: &C) -> Result<(), DbErr>
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

    #[test]
    fn stable_uuid() {
        // create a new license, ensure a new random state of the hashmap
        let license = || LicenseInfo {
            license: "LicenseRef-1-2-3".to_string(),
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
