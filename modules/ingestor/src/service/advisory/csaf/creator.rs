use crate::{
    graph::{
        advisory::advisory_vulnerability::{VersionInfo, VersionSpec},
        purl::creator::PurlCreator,
    },
    service::{advisory::csaf::util::resolve_identifier, Error},
};
use cpe::cpe::Cpe;
use cpe::uri::OwnedUri;
use csaf::{definitions::ProductIdT, Csaf};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, NotSet,
    QueryFilter,
};
use sea_query::IntoCondition;
use std::collections::HashSet;
use std::{collections::hash_map::Entry, collections::HashMap};
use trustify_common::{db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity as entity;
use uuid::Uuid;

#[derive(Debug, Eq, Hash, PartialEq)]
struct PurlStatus {
    cpe: Option<OwnedUri>,
    purl: Purl,
    status: &'static str,
    info: VersionInfo,
}

#[derive(Debug)]
pub struct PurlStatusCreator {
    advisory_id: Uuid,
    vulnerability_id: String,
    entries: HashSet<PurlStatus>,
}

impl PurlStatusCreator {
    pub fn new(advisory_id: Uuid, vulnerability_identifier: String) -> Self {
        Self {
            advisory_id,
            vulnerability_id: vulnerability_identifier,
            entries: HashSet::new(),
        }
    }

    pub fn add_all(&mut self, csaf: &Csaf, ps: &Option<Vec<ProductIdT>>, status: &'static str) {
        for r in ps.iter().flatten() {
            if let Some((cpe, Some(purl))) = resolve_identifier(csaf, r) {
                let mut package = Purl::from(purl.clone());
                package.qualifiers.clear();

                if let Some(version) = package.version.clone() {
                    let status = PurlStatus {
                        cpe: cpe.cloned(),
                        purl: package,
                        status,
                        info: VersionInfo {
                            scheme: "generic".to_string(),
                            spec: VersionSpec::Exact(version),
                        },
                    };

                    self.entries.insert(status);
                }
            }
        }
    }

    async fn check_status(
        status: &str,
        connection: &impl ConnectionTrait,
    ) -> Result<entity::status::Model, Error> {
        Ok(entity::status::Entity::find()
            .filter(entity::status::Column::Slug.eq(status))
            .one(connection)
            .await?
            .ok_or_else(|| crate::graph::error::Error::InvalidStatus(status.to_string()))?)
    }

    pub async fn create(self, connection: &impl ConnectionTrait) -> Result<(), Error> {
        let mut checked = HashMap::new();

        let mut purls = PurlCreator::new();

        for ps in &self.entries {
            // ensure a correct status, and get id
            if let Entry::Vacant(entry) = checked.entry(ps.status) {
                entry.insert(Self::check_status(ps.status, connection).await?);
            }
            // add to PURL creator
            purls.add(ps.purl.clone());
        }

        let mut cpes = HashMap::new();

        for ps in &self.entries {
            if let Some(cpe) = &ps.cpe {
                if let Some(found_cpe) = entity::cpe::Entity::find()
                    .filter(entity::cpe::Column::Part.eq(cpe.part().to_string()))
                    .filter(entity::cpe::Column::Vendor.eq(cpe.vendor().to_string()))
                    .filter(entity::cpe::Column::Product.eq(cpe.product().to_string()))
                    .filter(entity::cpe::Column::Version.eq(cpe.version().to_string()))
                    .filter(entity::cpe::Column::Update.eq(cpe.update().to_string()))
                    .filter(entity::cpe::Column::Edition.eq(cpe.edition().to_string()))
                    .filter(entity::cpe::Column::Language.eq(cpe.language().to_string()))
                    .one(connection)
                    .await?
                {
                    cpes.insert(cpe, found_cpe.id);
                } else {
                    let inserted_cpe = trustify_common::cpe::Cpe::from(cpe.clone());
                    let inserted_cpe = entity::cpe::ActiveModel::from(inserted_cpe);
                    let inserted_cpe = inserted_cpe.insert(connection).await?;
                    cpes.insert(cpe, inserted_cpe.id);
                }
            }
        }

        purls.create(connection).await?;

        // round two, status is checked, purls exist

        let mut version_ranges = Vec::new();
        let mut package_statuses = Vec::new();

        for ps in &self.entries {
            let status = checked.get(&ps.status).ok_or_else(|| {
                Error::Graph(crate::graph::error::Error::InvalidStatus(
                    ps.status.to_string(),
                ))
            })?;

            // TODO: we could try to batch process this too

            let package_id = ps.purl.package_uuid();

            let cpe_id = ps.cpe.as_ref().and_then(|inner| cpes.get(&inner));

            let package_status = entity::purl_status::Entity::find()
                .filter(entity::purl_status::Column::BasePurlId.eq(package_id))
                .filter(entity::purl_status::Column::AdvisoryId.eq(self.advisory_id))
                .filter(entity::purl_status::Column::StatusId.eq(status.id))
                .filter(
                    cpe_id
                        .map(|inner| entity::purl_status::Column::ContextCpeId.eq(*inner))
                        .unwrap_or(entity::purl_status::Column::ContextCpeId.is_null()),
                )
                .left_join(entity::version_range::Entity)
                .filter(ps.info.clone().into_condition())
                .one(connection)
                .await?;

            if package_status.is_some() {
                continue;
            }

            let mut version_range = ps.info.clone().into_active_model();
            let version_range_id = Uuid::now_v7();
            version_range.id = Set(version_range_id);
            version_ranges.push(version_range);

            let package_status = entity::purl_status::ActiveModel {
                id: Default::default(),
                advisory_id: Set(self.advisory_id),
                vulnerability_id: Set(self.vulnerability_id.clone()),
                status_id: Set(status.id),
                base_purl_id: Set(package_id),
                context_cpe_id: cpe_id.map(|inner| Set(Some(*inner))).unwrap_or(NotSet),
                version_range_id: Set(version_range_id),
            };

            package_statuses.push(package_status);
        }

        // batch insert

        for batch in &version_ranges.chunked() {
            entity::version_range::Entity::insert_many(batch)
                .exec(connection)
                .await?;
        }

        for batch in &package_statuses.chunked() {
            entity::purl_status::Entity::insert_many(batch)
                .exec(connection)
                .await?;
        }

        // done

        Ok(())
    }
}
