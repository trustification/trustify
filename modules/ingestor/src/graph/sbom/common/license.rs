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

/// SPDX license information extracted from an SPDX expression
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SPDXInfo {
    pub spdx_licenses: Vec<String>,
    pub spdx_license_exceptions: Vec<String>,
    pub custom_license_refs: Vec<String>,
    pub custom_document_license_refs: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LicenseInfo {
    pub license: String,
}

impl LicenseInfo {
    pub fn uuid(&self) -> Uuid {
        // UUID based upon a hash of the lowercase de-ref'd license.
        Uuid::new_v5(&NAMESPACE, self.license.to_lowercase().as_bytes())
    }

    pub fn spdx_info(&self) -> SPDXInfo {
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

                let custom_document_license_refs = parsed
                    .licenses()
                    .iter()
                    .filter(|e| e.license_ref && e.document_ref.is_some())
                    .filter_map(|e| {
                        e.document_ref.as_ref().map(|doc_ref| {
                            format!("DocumentRef-{}:LicenseRef-{}", doc_ref, e.identifier)
                        })
                    })
                    .collect::<Vec<_>>();

                SPDXInfo {
                    spdx_licenses,
                    spdx_license_exceptions,
                    custom_license_refs,
                    custom_document_license_refs,
                }
            })
            .unwrap_or(SPDXInfo {
                spdx_licenses: vec![],
                spdx_license_exceptions: vec![],
                custom_license_refs: vec![],
                custom_document_license_refs: vec![],
            })
    }
}

pub struct LicenseBuilder {
    pub license_info: LicenseInfo,
}

impl LicenseBuilder {
    pub fn new(license_info: LicenseInfo) -> Self {
        Self { license_info }
    }

    pub fn to_active_model(&self) -> license::ActiveModel {
        let spdx_info = self.license_info.spdx_info();

        license::ActiveModel {
            id: Set(self.license_info.uuid()),
            text: Set(self.license_info.license.clone()),
            spdx_licenses: if spdx_info.spdx_licenses.is_empty() {
                Set(None)
            } else {
                Set(Some(spdx_info.spdx_licenses))
            },
            spdx_license_exceptions: if spdx_info.spdx_license_exceptions.is_empty() {
                Set(None)
            } else {
                Set(Some(spdx_info.spdx_license_exceptions))
            },
            custom_license_refs: if spdx_info.custom_license_refs.is_empty() {
                Set(None)
            } else {
                Set(Some(spdx_info.custom_license_refs))
            },
            custom_document_license_refs: if spdx_info.custom_document_license_refs.is_empty() {
                Set(None)
            } else {
                Set(Some(spdx_info.custom_document_license_refs))
            },
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct LicenseCreator {
    /// The licenses to create.
    ///
    /// Uses a [`BTreeMap`] to ensure we have a stable insertion order, avoiding deadlocks on the
    /// database.
    pub licenses: BTreeMap<Uuid, license::ActiveModel>,

    /// Custom license lookup map: license_id -> name
    custom_license_map: std::collections::HashMap<String, String>,
}

impl LicenseCreator {
    pub fn new() -> Self {
        Self {
            licenses: Default::default(),
            custom_license_map: std::collections::HashMap::new(),
        }
    }

    pub fn put_custom_license_list(
        &mut self,
        custom_license_list: &[licensing_infos::ActiveModel],
    ) {
        self.custom_license_map = custom_license_list
            .iter()
            .filter_map(|c| {
                if let (Set(license_id), Set(name)) = (&c.license_id, &c.name) {
                    Some((license_id.clone(), name.clone()))
                } else {
                    None
                }
            })
            .collect();
    }

    pub fn add(&mut self, info: &LicenseInfo) {
        let uuid = info.uuid();

        let spdx_info = info.spdx_info();
        let missing_custom_refs: Vec<_> = spdx_info
            .custom_license_refs
            .iter()
            .filter(|ref_id| !self.custom_license_map.contains_key(*ref_id))
            .cloned()
            .collect();
        if !missing_custom_refs.is_empty() {
            log::warn!(
                "The following custom license refs are missing from custom_license_list: {:?}",
                missing_custom_refs
            );
        }
        let custom_license_refs_value = if spdx_info.custom_license_refs.is_empty() {
            None
        } else {
            Some(self.construct_custom_license(spdx_info.custom_license_refs.clone()))
        };

        let mut active_model = LicenseBuilder::new(info.clone()).to_active_model();

        // Update custom_license_refs with constructed value
        if let Some(refs) = custom_license_refs_value {
            active_model.custom_license_refs = Set(Some(refs));
        }

        self.licenses.entry(uuid).or_insert(active_model);
    }

    fn construct_custom_license(&self, custom_license_ids: Vec<String>) -> Vec<String> {
        custom_license_ids
            .into_iter()
            .filter_map(|id| {
                self.custom_license_map
                    .get(&id)
                    .map(|name| format!("{}:{}", id, name))
            })
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
