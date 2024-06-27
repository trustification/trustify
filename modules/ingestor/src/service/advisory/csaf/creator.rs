use crate::{
    graph::{
        advisory::advisory_vulnerability::{VersionInfo, VersionSpec},
        purl::creator::PurlCreator,
    },
    service::{advisory::csaf::util::resolve_purls, Error},
};
use csaf::{definitions::ProductIdT, Csaf};
use sea_orm::{ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use sea_query::IntoCondition;
use std::{collections::hash_map::Entry, collections::HashMap};
use trustify_common::{db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::{package_status, status, version_range};
use uuid::Uuid;

#[derive(Debug, PartialEq)]
struct PackageStatus {
    package: Purl,
    status: &'static str,
    info: VersionInfo,
}

pub struct PackageStatusCreator {
    advisory_id: Uuid,
    vulnerability_id: i32,
    entries: Vec<PackageStatus>,
}

impl PackageStatusCreator {
    pub fn new(advisory_id: Uuid, vulnerability_id: i32) -> Self {
        Self {
            advisory_id,
            vulnerability_id,
            entries: Vec::new(),
        }
    }

    pub fn add_all(&mut self, csaf: &Csaf, ps: &Option<Vec<ProductIdT>>, status: &'static str) {
        for r in ps.iter().flatten() {
            for purl in resolve_purls(csaf, r) {
                let mut package = Purl::from(purl.clone());
                package.qualifiers.clear();

                if let Some(version) = package.version.clone() {
                    let status = PackageStatus {
                        package,
                        status,
                        info: VersionInfo {
                            scheme: "generic".to_string(),
                            spec: VersionSpec::Exact(version),
                        },
                    };

                    if !self.entries.contains(&status) {
                        self.entries.push(status);
                    }
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

    pub async fn create(self, connection: &impl ConnectionTrait) -> Result<(), Error> {
        let mut checked = HashMap::new();

        let mut purls = PurlCreator::new();

        for ps in &self.entries {
            // ensure a correct status, and get id
            if let Entry::Vacant(entry) = checked.entry(ps.status) {
                entry.insert(Self::check_status(ps.status, connection).await?);
            }
            // add to PURL creator
            purls.add(ps.package.clone());
        }

        purls.create(connection).await?;

        // round two, status is checked, purls exist

        let mut version_ranges = Vec::new();
        let mut package_statuses = Vec::new();

        for ps in self.entries {
            let status = checked.get(&ps.status).ok_or_else(|| {
                Error::Graph(crate::graph::error::Error::InvalidStatus(
                    ps.status.to_string(),
                ))
            })?;

            // TODO: we could try to batch process this too

            let package_id = ps.package.package_uuid();

            let package_status = package_status::Entity::find()
                .filter(package_status::Column::PackageId.eq(package_id))
                .filter(package_status::Column::AdvisoryId.eq(self.advisory_id))
                .filter(package_status::Column::StatusId.eq(status.id))
                .left_join(version_range::Entity)
                .filter(ps.info.clone().into_condition())
                .one(connection)
                .await?;

            if package_status.is_some() {
                continue;
            }

            let mut version_range = ps.info.into_active_model();
            let version_range_id = Uuid::now_v7();
            version_range.id = Set(version_range_id);
            version_ranges.push(version_range);

            let package_status = package_status::ActiveModel {
                id: Default::default(),
                advisory_id: Set(self.advisory_id),
                vulnerability_id: Set(self.vulnerability_id),
                status_id: Set(status.id),
                package_id: Set(package_id),
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
            package_status::Entity::insert_many(batch)
                .exec(connection)
                .await?;
        }

        // done

        Ok(())
    }
}
