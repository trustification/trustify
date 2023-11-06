use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, ModelTrait, QueryFilter, QuerySelect, QueryTrait, RelationTrait, Set, TransactionTrait};
use sea_query::{Condition, JoinType};
use spdx_rs::models::{RelationshipType, SPDX};

use crate::system::System;
use huevos_common::purl::Purl;
use huevos_entity::sbom::Model;
use huevos_entity::{package, package_qualifier, sbom, sbom_cpe, sbom_dependency, sbom_package};

use super::error::Error;

impl System {
    pub async fn ingest_sbom(&self, location: &str) -> Result<sbom::Model, Error> {
        let fetch = sbom::Entity::find()
            .filter(Condition::all().add(sbom::Column::Location.eq(location.clone())))
            .one(&*self.db)
            .await?;

        match fetch {
            None => {
                let model = sbom::ActiveModel {
                    location: Set(location.to_string()),
                    ..Default::default()
                };

                Ok(model.insert(&*self.db).await?)
            }
            Some(model) => Ok(model),
        }
    }

    pub async fn fetch_sbom(&self, location: &str) -> Result<Option<sbom::Model>, Error> {
        Ok(sbom::Entity::find()
            .filter(sbom::Column::Location.eq(location.to_string()))
            .one(&*self.db)
            .await?)
    }

    async fn ingest_sbom_cpe(
        &self,
        sbom: &sbom::Model,
        cpe: &str,
        tx: &DatabaseTransaction,
    ) -> Result<(), Error> {
        let fetch = sbom_cpe::Entity::find()
            .filter(Condition::all().add(sbom_cpe::Column::SbomId.eq(sbom.id)))
            .one(&*self.db)
            .await?;

        if fetch.is_none() {
            let model = sbom_cpe::ActiveModel {
                sbom_id: Set(sbom.id),
                cpe: Set(cpe.to_string()),
            };

            model.insert(tx).await?;
        }
        Ok(())
    }

    async fn ingest_sbom_package<P: Into<Purl>>(
        &self,
        sbom: &sbom::Model,
        package: P,
        tx: &DatabaseTransaction,
    ) -> Result<(), Error> {
        let fetch = sbom_package::Entity::find()
            .filter(Condition::all().add(sbom_package::Column::SbomId.eq(sbom.id)))
            .one(&*self.db)
            .await?;

        if fetch.is_none() {
            let package = self.ingest_package(package.into()).await?;
            let model = sbom_package::ActiveModel {
                sbom_id: Set(sbom.id),
                package_id: Set(package.id),
            };

            model.insert(tx).await?;
        }
        Ok(())
    }

    async fn ingest_sbom_dependency<P: Into<Purl>>(
        &self,
        sbom: sbom::Model,
        dependency: P,
        tx: &DatabaseTransaction,
    ) -> Result<(), Error> {
        let dependency = self.ingest_package(dependency).await?;

        if sbom_dependency::Entity::find()
            .filter(
                Condition::all()
                    .add(sbom_dependency::Column::PackageId.eq(dependency.id))
                    .add(sbom_dependency::Column::SbomId.eq(sbom.id)),
            )
            .one(&*self.db)
            .await?
            .is_none()
        {
            let entity = sbom_dependency::ActiveModel {
                sbom_id: Set(sbom.id),
                package_id: Set(dependency.id),
            };

            entity.insert(&*self.db).await?;
        }

        Ok(())
    }

    async fn ingest_spdx_sbom_data(
        &self,
        sbom: sbom::Model,
        sbom_data: SPDX,
    ) -> Result<(), anyhow::Error> {
        // FIXME: not sure this is correct. It may be that we need to use `DatabaseTransaction` instead of the `db` field
        let system = self.clone();
        self.db
            .transaction(|tx| {
                Box::pin(async move {
                    // For each thing described in the SBOM data, link it up to an sbom_cpe or sbom_package.
                    for described in &sbom_data.document_creation_information.document_describes {
                        if let Some(described_package) = sbom_data
                            .package_information
                            .iter()
                            .find(|each| each.package_spdx_identifier.eq(described))
                        {
                            for reference in &described_package.external_reference {
                                if reference.reference_type == "purl" {
                                    system
                                        .ingest_sbom_package(
                                            &sbom,
                                            reference.reference_locator.clone(),
                                            tx,
                                        )
                                        .await?;
                                } else if reference.reference_type == "cpe22Type" {
                                    system
                                        .ingest_sbom_cpe(&sbom, &reference.reference_locator, tx)
                                        .await?;
                                }
                            }

                            // Add any first-order dependencies from SBOM->purl
                            for described_reference in &described_package.external_reference {
                                for relationship in
                                    &sbom_data.relationships_for_related_spdx_id(described)
                                {
                                    if relationship.relationship_type
                                        == RelationshipType::ContainedBy
                                    {
                                        if let Some(package) =
                                            sbom_data.package_information.iter().find(|each| {
                                                each.package_spdx_identifier
                                                    == relationship.spdx_element_id
                                            })
                                        {
                                            for reference in &package.external_reference {
                                                if reference.reference_type == "purl" {
                                                    system
                                                        .ingest_sbom_dependency(
                                                            sbom.clone(),
                                                            reference.reference_locator.clone(),
                                                            tx,
                                                        )
                                                        .await?;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // connect all other tree-ish package trees in the context of this sbom.
                            for package_info in &sbom_data.package_information {
                                let package_identifier = &package_info.package_spdx_identifier;
                                for package_ref in &package_info.external_reference {
                                    if package_ref.reference_type == "purl" {
                                        for relationship in sbom_data
                                            .relationships_for_related_spdx_id(&package_identifier)
                                        {
                                            if relationship.relationship_type
                                                == RelationshipType::ContainedBy
                                            {
                                                if let Some(package) = sbom_data
                                                    .package_information
                                                    .iter()
                                                    .find(|each| {
                                                        each.package_spdx_identifier
                                                            == relationship.spdx_element_id
                                                    })
                                                {
                                                    for reference in &package.external_reference {
                                                        if reference.reference_type == "purl" {
                                                            system
                                                                .ingest_package_dependency(
                                                                    package_ref
                                                                        .reference_locator
                                                                        .clone(),
                                                                    reference
                                                                        .reference_locator
                                                                        .clone(),
                                                                    &sbom,
                                                                )
                                                                .await?;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Ok::<(), Error>(())
                })
            })
            .await?;

        /*
        println!("DESCRIBES {:?}", describes);

        println!("--------packages--");
        for pkg in &sbom.package_information {
            for reference in &pkg.external_reference {
                if reference.reference_type == "purl" {
                    println!("{:#?}", reference.reference_locator);
                    package_system.ingest_package(
                        &*reference.reference_locator
                    ).await?;
                }
            }
        }

         */

        Ok(())
    }

    pub async fn direct_sbom_dependencies(&self, location: &str) -> Result<Vec<Purl>, Error> {
        if let Some(sbom) = self.fetch_sbom(location).await? {
            let found = package::Entity::find()
                .join(
                    JoinType::LeftJoin,
                    sbom_dependency::Relation::Package.def().rev()
                )
                .filter(sbom_dependency::Column::SbomId.eq( sbom.id))
                .find_with_related(package_qualifier::Entity)
                .all(&*self.db)
                .await?;

            Ok(self.packages_to_purls(found)?)
        } else {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::TransactionTrait;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Instant;

    use crate::system::error::Error;
    use spdx_rs::models::SPDX;

    use crate::system::System;

    #[tokio::test]
    async fn debug() -> Result<(), anyhow::Error> {
        env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .init();
        let system = System::for_test("debug").await?;

        let inner_system = system.clone();
        let db = inner_system.db.clone();

        db.transaction(|tx| {
            Box::pin(async move {
                let sbom = inner_system.ingest_sbom("test.com/sbom.json").await?;

                inner_system
                    .ingest_sbom_dependency(sbom.clone(), "pkg://maven/foo@1?type=jar", tx)
                    .await?;
                Ok::<(), Error>(())
            })
        })
        .await?;

        let result = system.direct_sbom_dependencies(
            "test.com/sbom.json"
        ).await?;

        println!("{:#?}", result);

        Ok(())
    }

    #[tokio::test]
    async fn parse_spdx() -> Result<(), anyhow::Error> {
        let system = System::for_test("parse_spdx").await?;

        let pwd = PathBuf::from_str(env!("PWD"))?;
        let test_data = pwd.join("test-data");

        //let sbom = test_data.join( "openshift-4.13.json");
        let sbom = test_data.join("ubi9-9.2-755.1697625012.json");

        let sbom = File::open(sbom)?;

        let start = Instant::now();
        let sbom_data: SPDX = serde_json::from_reader(sbom)?;
        let parse_time = start.elapsed();

        let start = Instant::now();
        let sbom = system.ingest_sbom("test.com/my-sbom.json").await?;
        system.ingest_spdx_sbom_data(sbom, sbom_data).await?;
        let ingest_time = start.elapsed();
        let start = Instant::now();

        //for pkg in system.package().packages().await? {
        //println!("{}", pkg);
        //}

        /*
        let deps = package_system.transitive_dependencies(
            "pkg:oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012"
        ).await?;
         */

        //let deps = system.direct_dependencies(
        //"pkg:oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012"
        //).await?;

        let deps = system
            .direct_sbom_dependencies("test.com/my-sbom.json")
            .await?;

        println!("{:#?}", deps);

        let query_time = start.elapsed();

        println!("parse {}ms", parse_time.as_millis());
        println!("ingest {}ms", ingest_time.as_millis());
        println!("query {}ms", query_time.as_millis());

        Ok(())
    }
}
