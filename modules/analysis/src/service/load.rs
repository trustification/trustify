use crate::{model::PackageNode, service::AnalysisService};
use petgraph::Graph;
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, QueryResult, Statement};
use std::collections::HashMap;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::{cpe::CpeDto, relationship::Relationship};
use uuid::Uuid;

pub async fn get_implicit_relationships<C: ConnectionTrait>(
    connection: &C,
    distinct_sbom_id: &str,
) -> Result<Vec<QueryResult>, DbErr> {
    let sql = r#"
        SELECT
             sbom.document_id,
             sbom.sbom_id,
             sbom.published::text,
             array_agg(get_purl(t1.qualified_purl_id)) as purl,
             array_agg(row_to_json(t2_cpe)) AS cpe,
             t1_node.node_id AS node_id,
             t1_node.name AS node_name,
             t1_version.version AS node_version,
             product.name AS product_name,
             product_version.version AS product_version
        FROM
            sbom
        LEFT JOIN
            product_version ON sbom.sbom_id = product_version.sbom_id
        LEFT JOIN
            product ON product_version.product_id = product.id
        LEFT JOIN
            sbom_node t1_node ON sbom.sbom_id = t1_node.sbom_id
        LEFT JOIN
            package_relates_to_package prtp ON t1_node.node_id = prtp.left_node_id OR t1_node.node_id = prtp.right_node_id
        LEFT JOIN
            sbom_package_purl_ref t1 ON t1.sbom_id = sbom.sbom_id AND t1_node.node_id = t1.node_id
        LEFT JOIN
            sbom_package_cpe_ref t2 ON t2.sbom_id = sbom.sbom_id AND t1_node.node_id = t2.node_id
        LEFT JOIN
            cpe t2_cpe ON t2.cpe_id = t2_cpe.id
        LEFT JOIN
            sbom_package t1_version ON t1_version.sbom_id = sbom.sbom_id AND t1_node.node_id = t1_version.node_id
        WHERE
            prtp.left_node_id IS NULL AND prtp.right_node_id IS NULL
          AND
            sbom.sbom_id = $1
        GROUP BY
            sbom.document_id,
            sbom.sbom_id,
            sbom.published,
            t1_node.node_id,
            t1_node.name,
            t1_version.version,
            product.name,
            product_version.version
        "#;

    let uuid = match Uuid::parse_str(distinct_sbom_id) {
        Ok(uuid) => uuid,
        Err(_) => return Err(DbErr::Custom("Invalid SBOM ID".to_string())),
    };
    let stmt = Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, [uuid.into()]);
    let results: Vec<QueryResult> = connection.query_all(stmt).await?;

    Ok(results)
}

pub async fn get_relationships<C: ConnectionTrait>(
    connection: &C,
    distinct_sbom_id: &str,
) -> Result<Vec<QueryResult>, DbErr> {
    // Retrieve all SBOM components that have defined relationships
    let sql = r#"
        SELECT
            sbom.document_id,
            sbom.sbom_id,
            sbom.published::text,
            package_relates_to_package.left_node_id AS left_node_id,
            array_agg(get_purl(t1.qualified_purl_id)) AS left_qualified_purl,
            array_agg(row_to_json(t3_cpe)) AS left_cpe,
            t1_node.name AS left_node_name,
            t1_version.version AS left_node_version,
            package_relates_to_package.relationship,
            package_relates_to_package.right_node_id AS right_node_id,
            array_agg(get_purl(t2.qualified_purl_id)) AS right_qualified_purl,
            array_agg(row_to_json(t4_cpe)) AS right_cpe,
            t2_node.name AS right_node_name,
            t2_version.version AS right_node_version,
            product.name AS product_name,
            product_version.version AS product_version
        FROM
            sbom
        LEFT JOIN
            product_version ON sbom.sbom_id = product_version.sbom_id
        LEFT JOIN
            product ON product_version.product_id = product.id
        LEFT JOIN
            package_relates_to_package ON sbom.sbom_id = package_relates_to_package.sbom_id
        LEFT JOIN
            sbom_package_purl_ref t1 ON sbom.sbom_id = t1.sbom_id AND t1.node_id = package_relates_to_package.left_node_id
        LEFT JOIN
            sbom_package_cpe_ref t3 ON sbom.sbom_id = t3.sbom_id AND t3.node_id = package_relates_to_package.left_node_id
        LEFT JOIN
            sbom_node t1_node ON sbom.sbom_id = t1_node.sbom_id AND t1_node.node_id = package_relates_to_package.left_node_id
        LEFT JOIN
            sbom_package t1_version ON sbom.sbom_id = t1_version.sbom_id AND t1_version.node_id = package_relates_to_package.left_node_id
        LEFT JOIN
            sbom_package_purl_ref t2 ON sbom.sbom_id = t2.sbom_id AND t2.node_id = package_relates_to_package.right_node_id
        LEFT JOIN
            sbom_package_cpe_ref t4 ON sbom.sbom_id = t4.sbom_id AND t4.node_id = package_relates_to_package.right_node_id
        LEFT JOIN
            sbom_node t2_node ON sbom.sbom_id = t2_node.sbom_id AND t2_node.node_id = package_relates_to_package.right_node_id
        LEFT JOIN
            sbom_package t2_version ON sbom.sbom_id = t2_version.sbom_id AND t2_version.node_id = package_relates_to_package.right_node_id
        LEFT JOIN
            cpe t3_cpe ON t3.cpe_id = t3_cpe.id
        LEFT JOIN
            cpe t4_cpe ON t4.cpe_id = t4_cpe.id
        WHERE
            package_relates_to_package.relationship IN (0, 1, 8, 9, 10, 13, 14, 15)
          AND
            sbom.sbom_id = $1
        GROUP BY
            sbom.document_id,
            sbom.sbom_id,
            sbom.published,
            package_relates_to_package.left_node_id,
            t1_node.name,
            t1_version.version,
            package_relates_to_package.relationship,
            package_relates_to_package.right_node_id,
            t2_node.name,
            t2_version.version,
            product.name,
            product_version.version
"#;

    let uuid = match Uuid::parse_str(distinct_sbom_id) {
        Ok(uuid) => uuid,
        Err(_) => return Err(DbErr::Custom("Invalid SBOM ID".to_string())),
    };
    let stmt = Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, [uuid.into()]);
    let results: Vec<QueryResult> = connection.query_all(stmt).await?;

    Ok(results)
}

fn to_purls(purls: Vec<String>) -> Vec<Purl> {
    purls
        .into_iter()
        .filter_map(|purl| Purl::try_from(purl).ok())
        .collect()
}

fn to_cpes(cpes: Vec<serde_json::Value>) -> Vec<Cpe> {
    cpes.into_iter()
        .flat_map(|cpe| {
            serde_json::from_value::<CpeDto>(cpe)
                .ok()
                .and_then(|cpe| Cpe::try_from(cpe).ok())
        })
        .collect()
}

impl AnalysisService {
    pub async fn load_graphs<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_ids: &Vec<String>,
    ) -> Result<(), DbErr> {
        for distinct_sbom_id in distinct_sbom_ids {
            if !self.graph.read().contains_key(distinct_sbom_id) {
                // lazy load graphs
                let mut g: Graph<PackageNode, Relationship, petgraph::Directed> = Graph::new();
                let mut nodes = HashMap::new();

                let mut describedby_node_id: Option<String> = Default::default();

                // Set relationships explicitly defined in SBOM
                match get_relationships(connection, &distinct_sbom_id.to_string()).await {
                    Ok(results) => {
                        for row in results {
                            let (
                                sbom_published,
                                document_id,
                                product_name,
                                product_version,
                                left_node_id,
                                left_purl_string,
                                left_cpe_json,
                                left_node_name,
                                left_node_version,
                                right_node_id,
                                right_purl_string,
                                right_cpe_json,
                                right_node_name,
                                right_node_version,
                                relationship,
                            ) = {
                                let default_value = "NOVALUE".to_string(); // TODO: this eventually will have different defaults.
                                (
                                    row.try_get("", "published")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "document_id")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "product_name")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "product_version")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "left_node_id")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get::<Vec<String>>("", "left_qualified_purl")
                                        .unwrap_or_default(),
                                    row.try_get("", "left_cpe")
                                        .ok()
                                        .unwrap_or_else(Vec::<serde_json::Value>::new),
                                    row.try_get("", "left_node_name")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "left_node_version")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "right_node_id")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get::<Vec<String>>("", "right_qualified_purl")
                                        .unwrap_or_default(),
                                    row.try_get("", "right_cpe")
                                        .ok()
                                        .unwrap_or_else(Vec::<serde_json::Value>::new),
                                    row.try_get("", "right_node_name")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "right_node_version")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "relationship")
                                        .unwrap_or(Relationship::ContainedBy),
                                )
                            };

                            /*log::info!(
                                "Row - left_node: {left_node_id:?}, right_node: {right_node_id:?}",
                            );
                            log::info!(
                                "Row - left_cpe: {left_cpe_json:?}, right_cpe: {right_cpe_json:?}",
                            );
                            log::info!(
                                "Row - left_purl: {left_purl_string:?}, right_purl: {right_purl_string:?}",
                            );*/

                            if relationship == Relationship::DescribedBy {
                                // Save for implicit relationships performed later
                                describedby_node_id = Some(left_node_id);
                            } else {
                                let p1 = match nodes.get(&left_node_id) {
                                    Some(&node_index) => node_index, // already exists
                                    None => {
                                        let new_node = PackageNode {
                                            sbom_id: distinct_sbom_id.clone(),
                                            node_id: left_node_id.clone(),
                                            purl: to_purls(left_purl_string.clone()),
                                            cpe: to_cpes(left_cpe_json),
                                            name: left_node_name.clone(),
                                            version: left_node_version.clone(),
                                            published: sbom_published.clone(),
                                            document_id: document_id.clone(),
                                            product_name: product_name.clone(),
                                            product_version: product_version.clone(),
                                        };
                                        let i = g.add_node(new_node);
                                        nodes.insert(left_node_id.clone(), i);
                                        i
                                    }
                                };

                                let p2 = match nodes.get(&right_node_id) {
                                    Some(&node_index) => node_index, // already exists
                                    None => {
                                        let new_node = PackageNode {
                                            sbom_id: distinct_sbom_id.clone(),
                                            node_id: right_node_id.clone(),
                                            purl: to_purls(right_purl_string.clone()),
                                            cpe: to_cpes(right_cpe_json),
                                            name: right_node_name.clone(),
                                            version: right_node_version.clone(),
                                            published: sbom_published.clone(),
                                            document_id: document_id.clone(),
                                            product_name: product_name.clone(),
                                            product_version: product_version.clone(),
                                        };
                                        let i = g.add_node(new_node);
                                        nodes.insert(right_node_id.clone(), i);
                                        i
                                    }
                                };

                                g.add_edge(p1, p2, relationship);
                            }
                        }
                    }
                    Err(err) => {
                        log::error!("Error fetching graph relationships: {}", err);
                    }
                }

                // Set relationships implicitly defined in SBOM
                match get_implicit_relationships(connection, &distinct_sbom_id.to_string()).await {
                    Ok(results) => {
                        for row in results {
                            let (
                                sbom_published,
                                document_id,
                                product_name,
                                product_version,
                                node_id,
                                purl,
                                cpe,
                                node_name,
                                node_version,
                            ) = {
                                let default_value = "NOVALUE".to_string(); // TODO: this eventually will have different defaults.
                                (
                                    row.try_get("", "published")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "document_id")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "product_name")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "product_version")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "node_id").unwrap_or(default_value.clone()),
                                    row.try_get::<Vec<String>>("", "purl").unwrap_or_default(),
                                    row.try_get("", "cpe")
                                        .ok()
                                        .unwrap_or_else(Vec::<serde_json::Value>::new),
                                    row.try_get("", "node_name")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "node_version")
                                        .unwrap_or(default_value.clone()),
                                )
                            };

                            let p1 = match nodes.get(&node_id) {
                                Some(&node_index) => node_index, // already exists
                                None => {
                                    let new_node = PackageNode {
                                        sbom_id: distinct_sbom_id.clone(),
                                        node_id: node_id.clone(),
                                        purl: to_purls(purl),
                                        cpe: to_cpes(cpe),
                                        name: node_name.clone(),
                                        version: node_version.clone(),
                                        published: sbom_published.clone(),
                                        document_id: document_id.clone(),
                                        product_name: product_name.clone(),
                                        product_version: product_version.clone(),
                                    };
                                    let i = g.add_node(new_node);
                                    nodes.insert(node_id.clone(), i);
                                    i
                                }
                            };

                            if let Some(describedby_node_index) =
                                describedby_node_id.as_ref().and_then(|id| nodes.get(id))
                            {
                                g.add_edge(p1, *describedby_node_index, Relationship::Undefined);
                            } else {
                                log::warn!("No 'describes' relationship found in {} SBOM, no implicit relationship set.", distinct_sbom_id);
                            }
                        }
                    }
                    Err(err) => {
                        log::error!("Error fetching graph relationships: {}", err);
                    }
                }

                self.graph.write().insert(distinct_sbom_id.to_string(), g);
            }
        }

        Ok(())
    }
}
