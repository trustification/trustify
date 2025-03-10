use sea_orm::ActiveValue::Set;
use sea_orm::{ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use std::collections::BTreeMap;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::licensing_infos;
use uuid::Uuid;

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LicensingInfo {
    pub id: Uuid,
    pub sbom_id: Uuid,
    pub license_id: String,
    pub name: String,
    pub extracted_text: String,
    pub comment: Option<String>,
}

impl LicensingInfo {
    pub fn uuid(sbom_id: Uuid, license_id: String) -> Uuid {
        let text = format!("{:?}{}", sbom_id, license_id);
        Uuid::new_v5(&NAMESPACE, text.to_lowercase().as_bytes())
    }
    pub fn with_sbom_id(
        sbom_id: Uuid,
        name: String,
        license_id: String,
        extracted_text: String,
        comment: Option<String>,
    ) -> Self {
        Self {
            id: LicensingInfo::uuid(sbom_id, license_id.clone()),
            sbom_id,
            license_id,
            name,
            extracted_text,
            comment,
        }
    }
}

pub struct LicensingInfoCreator {
    license_refs: BTreeMap<Uuid, licensing_infos::ActiveModel>,
}

impl Default for LicensingInfoCreator {
    fn default() -> Self {
        Self::new()
    }
}

impl LicensingInfoCreator {
    pub fn new() -> Self {
        Self {
            license_refs: Default::default(),
        }
    }

    pub fn add(&mut self, info: &LicensingInfo) {
        let uuid = info.clone().id;
        self.license_refs
            .entry(uuid)
            .or_insert(licensing_infos::ActiveModel {
                id: Set(info.id),
                sbom_id: Set(info.sbom_id),
                name: Set(info.name.clone()),
                license_id: Set(info.license_id.clone()),
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
            licensing_infos::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([licensing_infos::Column::Id])
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
