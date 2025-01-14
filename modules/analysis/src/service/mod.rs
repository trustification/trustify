mod load;
mod query;

#[cfg(test)]
mod test;

use crate::{
    model::{AnalysisStatus, AncNode, AncestorSummary, DepNode, DepSummary, GraphMap, PackageNode},
    Error,
};
use parking_lot::RwLock;
use petgraph::{
    algo::is_cyclic_directed,
    graph::{Graph, NodeIndex},
    visit::{NodeIndexable, VisitMap, Visitable},
    Direction,
};
use query::*;
use sea_orm::{
    prelude::ConnectionTrait, ColumnTrait, EntityOrSelect, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, RelationTrait,
};
use sea_query::{JoinType, Order, SelectStatement};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;
use tracing::instrument;
use trustify_common::{
    db::query::{Filtering, Value},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{
    relationship::Relationship, sbom, sbom_node, sbom_package, sbom_package_cpe_ref,
    sbom_package_purl_ref,
};
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct AnalysisService {
    graph: Arc<RwLock<GraphMap>>,
}

pub fn dep_nodes(
    graph: &Graph<PackageNode, Relationship, petgraph::Directed>,
    node: NodeIndex,
    visited: &mut HashSet<NodeIndex>,
) -> Vec<DepNode> {
    let mut depnodes = Vec::new();
    fn dfs(
        graph: &Graph<PackageNode, Relationship, petgraph::Directed>,
        node: NodeIndex,
        depnodes: &mut Vec<DepNode>,
        visited: &mut HashSet<NodeIndex>,
    ) {
        if visited.contains(&node) {
            return;
        }
        visited.insert(node);
        for neighbor in graph.neighbors_directed(node, Direction::Incoming) {
            if let Some(dep_packagenode) = graph.node_weight(neighbor).cloned() {
                // Attempt to find the edge and get the relationship in a more elegant way
                if let Some(relationship) = graph
                    .find_edge(neighbor, node)
                    .and_then(|edge_index| graph.edge_weight(edge_index))
                {
                    let dep_node = DepNode {
                        sbom_id: dep_packagenode.sbom_id,
                        node_id: dep_packagenode.node_id,
                        relationship: relationship.to_string(),
                        purl: dep_packagenode.purl.clone(),
                        cpe: dep_packagenode.cpe.clone(),
                        name: dep_packagenode.name.to_string(),
                        version: dep_packagenode.version.to_string(),
                        deps: dep_nodes(graph, neighbor, visited),
                    };
                    depnodes.push(dep_node);
                    dfs(graph, neighbor, depnodes, visited);
                }
            } else {
                log::warn!(
                    "Processing descendants node weight for neighbor {:?} not found",
                    neighbor
                );
            }
        }
    }

    dfs(graph, node, &mut depnodes, visited);

    depnodes
}

pub fn ancestor_nodes(
    graph: &Graph<PackageNode, Relationship, petgraph::Directed>,
    node: NodeIndex,
) -> Vec<AncNode> {
    let mut discovered = graph.visit_map();
    let mut ancestor_nodes = Vec::new();
    let mut stack = Vec::new();

    stack.push(graph.from_index(node.index()));

    while let Some(node) = stack.pop() {
        if discovered.visit(node) {
            for succ in graph.neighbors_directed(node, Direction::Outgoing) {
                if !discovered.is_visited(&succ) {
                    if let Some(anc_packagenode) = graph.node_weight(succ).cloned() {
                        if let Some(edge) = graph.find_edge(node, succ) {
                            if let Some(relationship) = graph.edge_weight(edge) {
                                let anc_node = AncNode {
                                    sbom_id: anc_packagenode.sbom_id,
                                    node_id: anc_packagenode.node_id,
                                    relationship: relationship.to_string(),
                                    purl: anc_packagenode.purl,
                                    cpe: anc_packagenode.cpe,
                                    name: anc_packagenode.name,
                                    version: anc_packagenode.version,
                                };
                                ancestor_nodes.push(anc_node);
                                stack.push(succ);
                            } else {
                                log::warn!(
                                    "Edge weight not found for edge between {:?} and {:?}",
                                    node,
                                    succ
                                );
                            }
                        } else {
                            log::warn!("Edge not found between {:?} and {:?}", node, succ);
                        }
                    } else {
                        log::warn!("Processing ancestors, node value for {:?} not found", succ);
                    }
                }
            }
            if graph.neighbors_directed(node, Direction::Outgoing).count() == 0 {
                continue; // we are at the root
            }
        }
    }
    ancestor_nodes
}

impl AnalysisService {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn load_all_graphs<C: ConnectionTrait>(&self, connection: &C) -> Result<(), Error> {
        // retrieve all sboms in trustify

        let distinct_sbom_ids = sbom::Entity::find()
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        self.load_graphs(connection, &distinct_sbom_ids).await?;

        Ok(())
    }

    pub fn clear_all_graphs(&self) -> Result<(), Error> {
        let mut manager = self.graph.write();
        manager.clear();
        Ok(())
    }

    pub async fn status<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<AnalysisStatus, Error> {
        let distinct_sbom_ids = sbom::Entity::find()
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?;

        let manager = self.graph.read();
        Ok(AnalysisStatus {
            sbom_count: distinct_sbom_ids.len() as u32,
            graph_count: manager.len() as u32,
        })
    }

    pub fn query_ancestor_graph<'a>(
        &self,
        query: impl Into<GraphQuery<'a>>,
        distinct_sbom_ids: Vec<String>,
    ) -> Vec<AncestorSummary> {
        let query = query.into();
        let mut components = Vec::new();

        // RwLock for reading hashmap<graph>
        let graph_read_guard = self.graph.read();
        for distinct_sbom_id in &distinct_sbom_ids {
            if let Some(graph) = graph_read_guard.get(distinct_sbom_id.to_string().as_str()) {
                if is_cyclic_directed(graph) {
                    log::warn!(
                        "analysis graph of sbom {} has circular references!",
                        distinct_sbom_id
                    );
                }

                let mut visited = HashSet::new();

                // Iterate over matching node indices and process them directly
                graph
                    .node_indices()
                    .filter(|&i| {
                        match &query {
                            GraphQuery::Component(ComponentReference::Name(name)) => graph
                                .node_weight(i)
                                .map(|node| node.name.eq(name))
                                .unwrap_or(false),
                            GraphQuery::Component(ComponentReference::Purl(component_purl)) => {
                                if let Some(node) = graph.node_weight(i) {
                                    node.purl.contains(component_purl)
                                } else {
                                    false // Return false if the node does not exist
                                }
                            }
                            GraphQuery::Component(ComponentReference::Cpe(component_cpe)) => {
                                if let Some(node) = graph.node_weight(i) {
                                    node.cpe.contains(component_cpe)
                                } else {
                                    false // Return false if the node does not exist
                                }
                            }
                            GraphQuery::Query(query) => graph
                                .node_weight(i)
                                .map(|node| {
                                    query.apply(&HashMap::from([
                                        ("sbom_id", Value::String(&node.sbom_id)),
                                        ("node_id", Value::String(&node.node_id)),
                                        ("name", Value::String(&node.name)),
                                        ("version", Value::String(&node.version)),
                                    ]))
                                })
                                .unwrap_or(false),
                        }
                    })
                    .for_each(|node_index| {
                        if !visited.contains(&node_index) {
                            visited.insert(node_index);

                            if let Some(find_match_package_node) = graph.node_weight(node_index) {
                                log::debug!("matched!");
                                components.push(AncestorSummary {
                                    sbom_id: find_match_package_node.sbom_id.to_string(),
                                    node_id: find_match_package_node.node_id.to_string(),
                                    purl: find_match_package_node.purl.clone(),
                                    cpe: find_match_package_node.cpe.clone(),
                                    name: find_match_package_node.name.to_string(),
                                    version: find_match_package_node.version.to_string(),
                                    published: find_match_package_node.published.to_string(),
                                    document_id: find_match_package_node.document_id.to_string(),
                                    product_name: find_match_package_node.product_name.to_string(),
                                    product_version: find_match_package_node
                                        .product_version
                                        .to_string(),
                                    ancestors: ancestor_nodes(graph, node_index),
                                });
                            }
                        }
                    });
            }
        }

        drop(graph_read_guard);

        components
    }

    pub async fn query_deps_graph(
        &self,
        query: impl Into<GraphQuery<'_>>,
        distinct_sbom_ids: Vec<String>,
    ) -> Vec<DepSummary> {
        let query = query.into();

        let mut components = Vec::new();

        // RwLock for reading hashmap<graph>
        let graph_read_guard = self.graph.read();
        for distinct_sbom_id in &distinct_sbom_ids {
            if let Some(graph) = graph_read_guard.get(distinct_sbom_id.to_string().as_str()) {
                if is_cyclic_directed(graph) {
                    log::warn!(
                        "analysis graph of sbom {} has circular references!",
                        distinct_sbom_id
                    );
                }

                let mut visited = HashSet::new();

                // Iterate over matching node indices and process them directly
                graph
                    .node_indices()
                    .filter(|&i| {
                        match &query {
                            GraphQuery::Component(ComponentReference::Name(component_name)) => {
                                graph
                                    .node_weight(i)
                                    .map(|node| node.name.eq(component_name))
                                    .unwrap_or(false)
                            }
                            GraphQuery::Component(ComponentReference::Purl(component_purl)) => {
                                if let Some(node) = graph.node_weight(i) {
                                    node.purl.contains(component_purl)
                                } else {
                                    false // Return false if the node does not exist
                                }
                            }
                            GraphQuery::Component(ComponentReference::Cpe(component_cpe)) => {
                                if let Some(node) = graph.node_weight(i) {
                                    node.cpe.contains(component_cpe)
                                } else {
                                    false // Return false if the node does not exist
                                }
                            }
                            GraphQuery::Query(query) => graph
                                .node_weight(i)
                                .map(|node| {
                                    query.apply(&HashMap::from([
                                        ("sbom_id", Value::String(&node.sbom_id)),
                                        ("node_id", Value::String(&node.node_id)),
                                        ("name", Value::String(&node.name)),
                                        ("version", Value::String(&node.version)),
                                    ]))
                                })
                                .unwrap_or(false),
                        }
                    })
                    .for_each(|node_index| {
                        if !visited.contains(&node_index) {
                            visited.insert(node_index);

                            if let Some(find_match_package_node) = graph.node_weight(node_index) {
                                log::debug!("matched!");
                                components.push(DepSummary {
                                    sbom_id: find_match_package_node.sbom_id.to_string(),
                                    node_id: find_match_package_node.node_id.to_string(),
                                    purl: find_match_package_node.purl.clone(),
                                    cpe: find_match_package_node.cpe.clone(),
                                    name: find_match_package_node.name.to_string(),
                                    version: find_match_package_node.version.to_string(),
                                    published: find_match_package_node.published.to_string(),
                                    document_id: find_match_package_node.document_id.to_string(),
                                    product_name: find_match_package_node.product_name.to_string(),
                                    product_version: find_match_package_node
                                        .product_version
                                        .to_string(),
                                    deps: dep_nodes(graph, node_index, &mut HashSet::new()),
                                });
                            }
                        }
                    });
            }
        }

        drop(graph_read_guard);

        components
    }

    pub async fn retrieve_all_sbom_roots_by_name<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        component_name: String,
        connection: &C,
    ) -> Result<Vec<AncNode>, Error> {
        // This function searches for a component(s) by name in a specific sbom, then returns that components
        // root components.

        let distinct_sbom_ids = vec![sbom_id.to_string()];
        self.load_graphs(connection, &distinct_sbom_ids).await?;

        let components = self.query_ancestor_graph(
            GraphQuery::Component(ComponentReference::Name(&component_name)),
            distinct_sbom_ids,
        );

        let mut root_components = Vec::new();
        for component in components {
            if let Some(last_ancestor) = component.ancestors.last() {
                if !root_components.contains(last_ancestor) {
                    // we want distinct list
                    root_components.push(last_ancestor.clone());
                }
            }
        }

        Ok(root_components)
    }

    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_root_components<C: ConnectionTrait>(
        &self,
        query: impl Into<GraphQuery<'_>> + Debug,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<AncestorSummary>, Error> {
        let query = query.into();

        let distinct_sbom_ids = self.load_graphs_query(connection, query).await?;
        let components = self.query_ancestor_graph(query, distinct_sbom_ids);

        Ok(paginated.paginate_array(&components))
    }

    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_deps<C: ConnectionTrait>(
        &self,
        query: impl Into<GraphQuery<'_>> + Debug,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<DepSummary>, Error> {
        let query = query.into();

        let distinct_sbom_ids = self.load_graphs_query(connection, query).await?;
        let components = self.query_deps_graph(query, distinct_sbom_ids).await;

        Ok(paginated.paginate_array(&components))
    }

    /// Take a [`GraphQuery`] and load all required SBOMs
    async fn load_graphs_query<C: ConnectionTrait>(
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
}
