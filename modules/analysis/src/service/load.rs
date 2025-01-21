use crate::{
    model::PackageNode,
    service::{AnalysisService, ComponentReference, GraphQuery},
    Error,
};
use petgraph::{prelude::NodeIndex, Graph};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DbErr, EntityOrSelect, EntityTrait,
    FromQueryResult, QueryFilter, QueryOrder, QuerySelect, QueryTrait, RelationTrait, Statement,
};
use sea_query::{JoinType, Order, SelectStatement};
use serde_json::Value;
use std::collections::HashSet;
use std::{collections::hash_map::Entry, collections::HashMap};
use tracing::{instrument, Level};
use trustify_common::{cpe::Cpe, db::query::Filtering, purl::Purl};
use trustify_entity::{
    cpe::CpeDto, package_relates_to_package, relationship::Relationship, sbom, sbom_node,
    sbom_package, sbom_package_cpe_ref, sbom_package_purl_ref,
};
use uuid::Uuid;

#[derive(Debug, FromQueryResult)]
pub struct Node {
    pub document_id: Option<String>,
    pub published: String,
    pub purls: Option<Vec<String>>,
    pub cpes: Option<Vec<Value>>,
    pub node_id: String,
    pub node_name: String,
    pub node_version: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
}

#[derive(Debug, FromQueryResult)]
pub struct Edge {
    pub left_node_id: String,
    pub relationship: Relationship,
    pub right_node_id: String,
}

#[instrument(skip(connection))]
pub async fn get_nodes<C: ConnectionTrait>(
    connection: &C,
    distinct_sbom_id: Uuid,
) -> Result<Vec<Node>, DbErr> {
    let sql = r#"
        SELECT
             sbom.document_id,
             sbom.published::text,
             array_agg(get_purl(t1.qualified_purl_id)) FILTER (WHERE get_purl(t1.qualified_purl_id) IS NOT NULL) AS purls,
             array_agg(row_to_json(t2_cpe)) FILTER (WHERE row_to_json(t2_cpe) IS NOT NULL) AS cpes,
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
            sbom_package_purl_ref t1 ON t1.sbom_id = sbom.sbom_id AND t1_node.node_id = t1.node_id
        LEFT JOIN
            sbom_package_cpe_ref t2 ON t2.sbom_id = sbom.sbom_id AND t1_node.node_id = t2.node_id
        LEFT JOIN
            cpe t2_cpe ON t2.cpe_id = t2_cpe.id
        LEFT JOIN
            sbom_package t1_version ON t1_version.sbom_id = sbom.sbom_id AND t1_node.node_id = t1_version.node_id
        WHERE
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

    let stmt =
        Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, [distinct_sbom_id.into()]);

    Ok(Node::find_by_statement(stmt).all(connection).await?)
}

#[instrument(skip(connection))]
pub async fn get_relationships<C: ConnectionTrait>(
    connection: &C,
    distinct_sbom_id: Uuid,
) -> Result<Vec<Edge>, DbErr> {
    Ok(package_relates_to_package::Entity::find()
        .filter(package_relates_to_package::Column::SbomId.eq(distinct_sbom_id))
        .all(connection)
        .await?
        .into_iter()
        .map(|prtp| Edge {
            left_node_id: prtp.left_node_id,
            relationship: prtp.relationship,
            right_node_id: prtp.right_node_id,
        })
        .collect())
}

fn to_purls(purls: Option<Vec<String>>) -> Vec<Purl> {
    purls
        .into_iter()
        .flatten()
        .filter_map(|purl| Purl::try_from(purl).ok())
        .collect()
}

fn to_cpes(cpes: Option<Vec<Value>>) -> Vec<Cpe> {
    cpes.into_iter()
        .flatten()
        .flat_map(|cpe| {
            serde_json::from_value::<CpeDto>(cpe)
                .ok()
                .and_then(|cpe| Cpe::try_from(cpe).ok())
        })
        .collect()
}

impl AnalysisService {
    /// Take a [`GraphQuery`] and load all required SBOMs
    #[instrument(skip(self, connection), err(level=Level::INFO))]
    pub(crate) async fn load_graphs_query<C: ConnectionTrait>(
        &self,
        connection: &C,
        query: GraphQuery<'_>,
    ) -> Result<Vec<String>, Error> {
        let search_sbom_subquery = match query {
            GraphQuery::Component(ComponentReference::Name(name)) => sbom_node::Entity::find()
                .filter(sbom_node::Column::Name.eq(name))
                .select_only()
                .column(sbom_node::Column::SbomId)
                .distinct()
                .into_query(),
            GraphQuery::Component(ComponentReference::Purl(purl)) => sbom_node::Entity::find()
                .join(JoinType::Join, sbom_node::Relation::Package.def())
                .join(JoinType::Join, sbom_package::Relation::Purl.def())
                .filter(sbom_package_purl_ref::Column::QualifiedPurlId.eq(purl.qualifier_uuid()))
                .select_only()
                .column(sbom_node::Column::SbomId)
                .distinct()
                .into_query(),
            GraphQuery::Component(ComponentReference::Cpe(cpe)) => sbom_node::Entity::find()
                .join(JoinType::Join, sbom_node::Relation::Package.def())
                .join(JoinType::Join, sbom_package::Relation::Cpe.def())
                .filter(sbom_package_cpe_ref::Column::CpeId.eq(cpe.uuid()))
                .select_only()
                .column(sbom_node::Column::SbomId)
                .distinct()
                .into_query(),
            GraphQuery::Query(query) => sbom_node::Entity::find()
                .filtering(query.clone())?
                .select_only()
                .column(sbom_node::Column::SbomId)
                .distinct()
                .into_query(),
        };

        self.load_graphs_subquery(connection, search_sbom_subquery)
            .await
    }

    /// Take a select for sboms, and ensure they are loaded and return their IDs.
    async fn load_graphs_subquery<C: ConnectionTrait>(
        &self,
        connection: &C,
        subquery: SelectStatement,
    ) -> Result<Vec<String>, Error> {
        let distinct_sbom_ids: Vec<String> = sbom::Entity::find()
            .filter(sbom::Column::SbomId.in_subquery(subquery))
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        self.load_graphs(connection, &distinct_sbom_ids).await?;

        Ok(distinct_sbom_ids)
    }

    /// Load the SBOM matching the provided ID
    #[instrument(skip(self, connection))]
    pub async fn load_graph<C: ConnectionTrait>(&self, connection: &C, distinct_sbom_id: &str) {
        if self.graph.read().contains_key(distinct_sbom_id) {
            // early return if we already loaded it
            return;
        }

        let distinct_sbom_id = match Uuid::parse_str(distinct_sbom_id) {
            Ok(uuid) => uuid,
            Err(err) => {
                log::warn!("Unable to parse SBOM ID {distinct_sbom_id}: {err}");
                return;
            }
        };

        // lazy load graphs

        let mut g: Graph<PackageNode, Relationship, petgraph::Directed> = Graph::new();
        let mut nodes = HashMap::new();
        let mut detected_nodes = HashSet::new();

        // populate packages/components

        let packages = match get_nodes(connection, distinct_sbom_id).await {
            Ok(nodes) => nodes,
            Err(err) => {
                log::error!("Error fetching graph nodes: {}", err);
                return;
            }
        };

        for package in packages {
            detected_nodes.insert(package.node_id.clone());

            match nodes.entry(package.node_id.clone()) {
                Entry::Vacant(entry) => {
                    let index = g.add_node(PackageNode {
                        sbom_id: distinct_sbom_id.to_string(),
                        node_id: package.node_id,
                        purl: to_purls(package.purls),
                        cpe: to_cpes(package.cpes),
                        name: package.node_name,
                        version: package.node_version.clone().unwrap_or_default(),
                        published: package.published.clone(),
                        document_id: package.document_id.clone().unwrap_or_default(),
                        product_name: package.product_name.clone().unwrap_or_default(),
                        product_version: package.product_version.clone().unwrap_or_default(),
                    });

                    log::debug!("Inserting - id: {}, index: {index:?}", entry.key());

                    entry.insert(index);
                }
                Entry::Occupied(_) => {}
            }
        }

        // populate relationships

        let edges = match get_relationships(connection, distinct_sbom_id).await {
            Ok(edges) => edges,
            Err(err) => {
                log::error!("Error fetching graph relationships: {}", err);
                return;
            }
        };

        // the nodes describing the document
        let mut describedby_node_id: Vec<NodeIndex> = Default::default();

        for edge in edges {
            log::debug!("Adding edge {:?}", edge);

            // insert edge into the graph
            match (
                nodes.get(&edge.left_node_id),
                nodes.get(&edge.right_node_id),
            ) {
                (Some(left), Some(right)) => {
                    if edge.relationship == Relationship::DescribedBy {
                        describedby_node_id.push(*left);
                    }

                    // remove all node IDs we somehow connected
                    detected_nodes.remove(&edge.left_node_id);
                    detected_nodes.remove(&edge.right_node_id);

                    g.add_edge(*left, *right, edge.relationship);
                }
                _ => {}
            }
        }

        log::debug!("Describing nodes: {describedby_node_id:?}");
        log::debug!("Unconnected nodes: {detected_nodes:?}");

        if !describedby_node_id.is_empty() {
            // search of unconnected nodes and create undefined relationships
            // all nodes not removed are unconnected
            for id in detected_nodes {
                let Some(id) = nodes.get(&id) else { continue };
                // add "undefined" relationship
                for from in &describedby_node_id {
                    log::debug!("Creating undefined relationship - left: {id:?}, right: {from:?}");
                    g.add_edge(*id, *from, Relationship::Undefined);
                }
            }
        }

        // Set the result. A parallel call might have done the same. We wasted some time, but the
        // state is still correct.

        self.graph.write().insert(distinct_sbom_id.to_string(), g);
    }

    /// Load all SBOMs by the provided IDs
    pub async fn load_graphs<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_ids: &Vec<String>,
    ) -> Result<(), DbErr> {
        for distinct_sbom_id in distinct_sbom_ids {
            self.load_graph(connection, distinct_sbom_id).await;
        }

        Ok(())
    }
}
