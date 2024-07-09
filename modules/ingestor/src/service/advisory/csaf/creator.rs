use crate::{
    graph::{
        advisory::advisory_vulnerability::{VersionInfo, VersionSpec},
        cpe::CpeCreator,
        purl::creator::PurlCreator,
    },
    service::{advisory::csaf::util::resolve_identifier, Error},
};
use csaf::{definitions::ProductIdT, Csaf};
use sea_orm::{ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use sea_query::IntoCondition;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use tracing::instrument;
use trustify_common::{cpe::Cpe, db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::{purl_status, status, version_range};
use uuid::Uuid;

#[derive(Debug, Eq, Hash, PartialEq)]
struct PurlStatus {
    cpe: Option<Cpe>,
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
                let mut purl = Purl::from(purl.clone());
                purl.qualifiers.clear();

                if let Some(version) = purl.version.clone() {
                    let status = PurlStatus {
                        cpe: cpe.cloned().map(|cpe| cpe.into()),
                        purl,
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
    ) -> Result<status::Model, Error> {
        Ok(status::Entity::find()
            .filter(status::Column::Slug.eq(status))
            .one(connection)
            .await?
            .ok_or_else(|| crate::graph::error::Error::InvalidStatus(status.to_string()))?)
    }

    #[instrument(skip(self, connection), err)]
    pub async fn create(self, connection: &impl ConnectionTrait) -> Result<(), Error> {
        let mut checked = HashMap::new();

        let mut purls = PurlCreator::new();
        let mut cpes = CpeCreator::new();

        for ps in &self.entries {
            // ensure a correct status, and get id
            if let Entry::Vacant(entry) = checked.entry(ps.status) {
                entry.insert(Self::check_status(ps.status, connection).await?);
            }

            // add to PURL creator
            purls.add(ps.purl.clone());

            if let Some(cpe) = &ps.cpe {
                cpes.add(cpe.clone());
            }
        }

        purls.create(connection).await?;
        cpes.create(connection).await?;

        // round two, status is checked, purls exist

        let mut version_ranges = Vec::new();
        let mut package_statuses = Vec::new();

        for ps in &self.entries {
            let status = checked.get(&ps.status).ok_or_else(|| {
                Error::Graph(crate::graph::error::Error::InvalidStatus(
                    ps.status.to_string(),
                ))
            })?;

            let package_id = ps.purl.package_uuid();
            let cpe_id = ps.cpe.as_ref().map(Cpe::uuid);

            let package_status = purl_status::Entity::find()
                .filter(purl_status::Column::BasePurlId.eq(package_id))
                .filter(purl_status::Column::AdvisoryId.eq(self.advisory_id))
                .filter(purl_status::Column::VulnerabilityId.eq(&self.vulnerability_id))
                .filter(purl_status::Column::StatusId.eq(status.id))
                .filter(
                    cpe_id
                        .map(|inner| purl_status::Column::ContextCpeId.eq(inner))
                        .unwrap_or(purl_status::Column::ContextCpeId.is_null()),
                )
                .left_join(version_range::Entity)
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

            let package_status = purl_status::ActiveModel {
                id: Default::default(),
                advisory_id: Set(self.advisory_id),
                vulnerability_id: Set(self.vulnerability_id.clone()),
                status_id: Set(status.id),
                base_purl_id: Set(package_id),
                context_cpe_id: Set(cpe_id),
                version_range_id: Set(version_range_id),
            };

            package_statuses.push(package_status);
        }

        // batch insert

        for batch in &version_ranges.chunked() {
            version_range::Entity::insert_many(batch)
                .exec(connection)
                .await?;
        }

        for batch in &package_statuses.chunked() {
            purl_status::Entity::insert_many(batch)
                .exec(connection)
                .await?;
        }

        // done

        Ok(())
    }
}
