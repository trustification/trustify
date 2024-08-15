use sea_orm::ActiveValue::Set;
use sea_orm::{ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use std::collections::HashMap;
use trustify_entity::license;
use uuid::Uuid;

use spdx_expression::SpdxExpression;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

#[derive(Default, Debug, Clone)]
pub struct LicenseInfo {
    pub license: String,
    pub refs: HashMap<String, String>,
}

impl LicenseInfo {
    pub fn uuid(&self) -> Uuid {
        let mut text = self.license.clone();

        for (user_ref, user_license) in &self.refs {
            text = text.replace(user_ref, user_license);
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
    licenses: HashMap<Uuid, license::ActiveModel>,
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

    #[instrument(skip_all, fields(num = self.licenses.len()), err)]
    pub async fn create<'g, C>(self, db: &C) -> Result<(), DbErr>
    where
        C: ConnectionTrait,
    {
        if self.licenses.is_empty() {
            return Ok(());
        }

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
