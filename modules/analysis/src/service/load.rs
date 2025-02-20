use crate::{
    Error,
    model::{PackageGraph, PackageNode},
    service::{AnalysisService, ComponentReference, GraphQuery},
};
use anyhow::anyhow;
use petgraph::{Graph, prelude::NodeIndex};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DbErr, EntityOrSelect, EntityTrait,
    FromQueryResult, QueryFilter, QueryOrder, QuerySelect, QueryTrait, RelationTrait, Statement,
};
use sea_query::{JoinType, Order, SelectStatement};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::{collections::HashMap, collections::hash_map::Entry};
use tracing::{Level, instrument};
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
WITH
purl_ref AS (
    SELECT
        sbom_id,
        node_id,
        array_agg(get_purl(qualified_purl_id)) AS purls
    FROM
        sbom_package_purl_ref
    GROUP BY
        sbom_id,
        node_id
),
cpe_ref AS (
    SELECT
        sbom_id,
        node_id,
        array_agg(row_to_json(cpe)) AS cpes
    FROM
        sbom_package_cpe_ref
    LEFT JOIN
        cpe ON (sbom_package_cpe_ref.cpe_id = cpe.id)
    GROUP BY
        sbom_id,
        node_id
)
SELECT
    sbom.document_id,
    sbom.published::text,
    purl_ref.purls,
    cpe_ref.cpes,
    t1_node.node_id AS node_id,
    t1_node.name AS node_name,
    t1_package.version AS node_version,
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
    sbom_package t1_package ON t1_node.sbom_id = t1_package.sbom_id AND t1_node.node_id = t1_package.node_id
LEFT JOIN
    purl_ref ON purl_ref.sbom_id = sbom.sbom_id AND purl_ref.node_id = t1_node.node_id
LEFT JOIN
    cpe_ref ON cpe_ref.sbom_id = sbom.sbom_id AND cpe_ref.node_id = t1_node.node_id
WHERE
    sbom.sbom_id = $1
"#;

    let stmt =
        Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, [distinct_sbom_id.into()]);

    Node::find_by_statement(stmt).all(connection).await
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
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        let search_sbom_subquery = match query {
            GraphQuery::Component(ComponentReference::Id(name)) => sbom_node::Entity::find()
                .filter(sbom_node::Column::NodeId.eq(name))
                .select_only()
                .column(sbom_node::Column::SbomId)
                .distinct()
                .into_query(),
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
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
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

        self.load_graphs(connection, &distinct_sbom_ids).await
    }

    /// Load the SBOM matching the provided ID
    #[instrument(skip(self, connection))]
    pub async fn load_graph<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_id: &str,
    ) -> Result<Arc<PackageGraph>, Error> {
        if let Some(g) = self.graph_cache.get(distinct_sbom_id) {
            // early return if we already loaded it
            return Ok(g);
        }

        let distinct_sbom_id = match Uuid::parse_str(distinct_sbom_id) {
            Ok(uuid) => uuid,
            Err(err) => {
                return Err(Error::Database(anyhow!(
                    "Unable to parse SBOM ID {distinct_sbom_id}: {err}"
                )));
            }
        };

        // lazy load graphs

        let mut g: PackageGraph = Graph::new();
        let mut nodes = HashMap::new();
        let mut detected_nodes = HashSet::new();

        // populate packages/components

        let packages = match get_nodes(connection, distinct_sbom_id).await {
            Ok(nodes) => nodes,
            Err(err) => {
                return Err(err.into());
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
                return Err(err.into());
            }
        };

        // the nodes describing the document
        let mut describedby_node_id: HashSet<NodeIndex> = Default::default();

        for edge in edges {
            log::debug!("Adding edge {:?}", edge);

            // insert edge into the graph
            if let (Some(left), Some(right)) = (
                nodes.get(&edge.left_node_id),
                nodes.get(&edge.right_node_id),
            ) {
                if edge.relationship == Relationship::Describes {
                    describedby_node_id.insert(*left);
                }

                // remove all node IDs we somehow connected
                detected_nodes.remove(&edge.left_node_id);
                detected_nodes.remove(&edge.right_node_id);

                g.add_edge(*left, *right, edge.relationship);
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
                    log::debug!("Creating undefined relationship - left: {from:?}, right: {id:?}");
                    g.add_edge(*from, *id, Relationship::Undefined);
                }
            }
        }

        // Set the result. A parallel call might have done the same. We wasted some time, but the
        // state is still correct.

        let g = Arc::new(g);
        self.graph_cache
            .insert(distinct_sbom_id.to_string(), g.clone());
        Ok(g)
    }

    /// Load all SBOMs by the provided IDs
    pub async fn load_graphs<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_ids: &Vec<String>,
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        let mut results = Vec::new();
        for distinct_sbom_id in distinct_sbom_ids {
            results.push((
                distinct_sbom_id.clone(),
                self.load_graph(connection, distinct_sbom_id).await?,
            ));
        }
        Ok(results)
    }
}
