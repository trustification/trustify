mod load;
mod query;

pub use query::*;

#[cfg(test)]
mod test;

use crate::{
    model::{
        AnalysisStatus, AncNode, AncestorSummary, BaseSummary, DepNode, DepSummary, GraphMap,
        PackageNode,
    },
    Error,
};
use parking_lot::RwLock;
use petgraph::{
    algo::is_cyclic_directed,
    graph::{Graph, NodeIndex},
    visit::{NodeIndexable, VisitMap, Visitable},
    Direction,
};
use sea_orm::{prelude::ConnectionTrait, EntityOrSelect, EntityTrait, QueryOrder};
use sea_query::Order;
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    sync::Arc,
};
use tracing::instrument;
use trustify_common::{
    db::query::Value,
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{relationship::Relationship, sbom};
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
        for neighbor in graph.neighbors_directed(node, Direction::Outgoing) {
            if let Some(dep_packagenode) = graph.node_weight(neighbor).cloned() {
                // Attempt to find the edge and get the relationship in a more elegant way
                if let Some(relationship) = graph
                    .find_edge(node, neighbor)
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
            for succ in graph.neighbors_directed(node, Direction::Incoming) {
                if !discovered.is_visited(&succ) {
                    if let Some(anc_packagenode) = graph.node_weight(succ).cloned() {
                        if let Some(edge) = graph.find_edge(succ, node) {
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
            if graph.neighbors_directed(node, Direction::Incoming).count() == 0 {
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

    #[instrument(skip_all, err)]
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

    /// Collect nodes from the graph
    ///
    /// Similar to [`Self::query_graph`], but manages the state of collecting.
    #[instrument(skip(self, init, collector))]
    fn collect_graph<'a, T, I, C>(
        &self,
        query: impl Into<GraphQuery<'a>> + Debug,
        distinct_sbom_ids: Vec<String>,
        init: I,
        collector: C,
    ) -> T
    where
        I: FnOnce() -> T,
        C: Fn(&mut T, &Graph<PackageNode, Relationship>, NodeIndex, &PackageNode),
    {
        let mut value = init();

        self.query_graph(query, distinct_sbom_ids, |graph, index, node| {
            collector(&mut value, graph, index, node);
        });

        value
    }

    /// Traverse the graph, call the function for every matching node.
    #[instrument(skip(self, f))]
    fn query_graph<'a, F>(
        &self,
        query: impl Into<GraphQuery<'a>> + Debug,
        distinct_sbom_ids: Vec<String>,
        mut f: F,
    ) where
        F: FnMut(&Graph<PackageNode, Relationship>, NodeIndex, &PackageNode),
    {
        let query = query.into();

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
                    .filter(|&i| Self::filter(graph, &query, i))
                    .for_each(|node_index| {
                        if !visited.contains(&node_index) {
                            visited.insert(node_index);

                            if let Some(find_match_package_node) = graph.node_weight(node_index) {
                                log::debug!("matched!");
                                f(graph, node_index, find_match_package_node);
                            }
                        }
                    });
            }
        }
    }

    #[instrument(skip(self))]
    pub fn query_ancestor_graph<'a>(
        &self,
        query: impl Into<GraphQuery<'a>> + Debug,
        distinct_sbom_ids: Vec<String>,
    ) -> Vec<AncestorSummary> {
        self.collect_graph(
            query,
            distinct_sbom_ids,
            Vec::new,
            |components, graph, node_index, node| {
                components.push(AncestorSummary {
                    base: node.into(),
                    ancestors: ancestor_nodes(graph, node_index),
                });
            },
        )
    }

    #[instrument(skip(self))]
    pub async fn query_deps_graph(
        &self,
        query: impl Into<GraphQuery<'_>> + Debug,
        distinct_sbom_ids: Vec<String>,
    ) -> Vec<DepSummary> {
        self.collect_graph(
            query,
            distinct_sbom_ids,
            Vec::new,
            |components, graph, node_index, node| {
                components.push(DepSummary {
                    base: node.into(),
                    deps: dep_nodes(graph, node_index, &mut HashSet::new()),
                });
            },
        )
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
                    // we want a distinct list
                    root_components.push(last_ancestor.clone());
                }
            }
        }

        Ok(root_components)
    }

    /// locate components, retrieve ancestor information
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

    /// locate components, retrieve dependency information
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

    /// locate components, retrieve basic information only
    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_components<C: ConnectionTrait>(
        &self,
        query: impl Into<GraphQuery<'_>> + Debug,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<BaseSummary>, Error> {
        let query = query.into();

        let distinct_sbom_ids = self.load_graphs_query(connection, query).await?;
        let components = self.collect_graph(
            query,
            distinct_sbom_ids,
            Vec::new,
            |components, _, _, node| {
                components.push(BaseSummary::from(node));
            },
        );

        Ok(paginated.paginate_array(&components))
    }

    /// check if a node in the graph matches the provided query
    fn filter(graph: &Graph<PackageNode, Relationship>, query: &GraphQuery, i: NodeIndex) -> bool {
        match query {
            GraphQuery::Component(ComponentReference::Id(component_id)) => graph
                .node_weight(i)
                .map(|node| node.node_id.eq(component_id))
                .unwrap_or(false),
            GraphQuery::Component(ComponentReference::Name(component_name)) => graph
                .node_weight(i)
                .map(|node| node.name.eq(component_name))
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
    }
}
