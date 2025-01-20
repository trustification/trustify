use sea_orm::ActiveValue::Set;
use sea_orm::{ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use std::collections::BTreeMap;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::extracted_licensing_infos;
use uuid::Uuid;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExtratedLicensingInfo {
    pub id: Uuid,
    pub sbom_id: Uuid,
    pub license_id: String,
    pub name: String,
    pub extracted_text: String,
    pub comment: Option<String>,
}

impl ExtratedLicensingInfo {
    pub fn uuid(sbom_id: Uuid, licenseId: String) -> Uuid {
        let text = format!("{}{}", sbom_id.to_string(), licenseId);
        Uuid::new_v5(&NAMESPACE, text.to_lowercase().as_bytes())
    }
    pub fn with_sbom_id(
        sbom_id: Uuid,
        licenseId: String,
        name: String,
        extracted_text: String,
        comment: Option<String>,
    ) -> Self {
        Self {
            id: ExtratedLicensingInfo::uuid(sbom_id, licenseId.clone()),
            sbom_id: sbom_id,
            license_id: licenseId,
            name,
            extracted_text,
            comment,
        }
    }
}

pub struct ExtractedLicensingInfoCreator {
    license_refs: BTreeMap<Uuid, extracted_licensing_infos::ActiveModel>,
}

impl ExtractedLicensingInfoCreator {
    pub fn new() -> Self {
        Self {
            license_refs: Default::default(),
        }
    }

    pub fn add(&mut self, info: &ExtratedLicensingInfo) {
        let uuid = info.clone().id;
        self.license_refs
            .entry(uuid)
            .or_insert(extracted_licensing_infos::ActiveModel {
                id: Set(info.id.clone()),
                sbom_id: Set(info.sbom_id.clone()),
                licenseId: Set(info.license_id.clone()),
                // name: Set(info.name.clone()),
                extracted_text: Set(info.extracted_text.clone()),
                comment: if let Some(comment) = info.comment.clone() {
                    Set(comment)
                } else {
                    Set(String::default())
                },
            });
    }

    #[instrument(skip_all, fields(num = self.license_refs.len()), err)]
    pub async fn create<'g, C>(self, db: &C) -> Result<(), DbErr>
    where
        C: ConnectionTrait,
    {
        if self.license_refs.is_empty() {
            return Ok(());
        }
        for batch in &self.license_refs.into_values().chunked() {
            extracted_licensing_infos::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([extracted_licensing_infos::Column::Id])
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
