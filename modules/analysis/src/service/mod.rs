mod load;
mod query;
mod render;
mod walk;

pub use query::*;
pub use walk::*;

#[cfg(test)]
mod test;

use crate::{
    model::{AnalysisStatus, BaseSummary, GraphMap, Node, PackageNode, Roots},
    Error,
};
use fixedbitset::FixedBitSet;
use parking_lot::RwLock;
use petgraph::{
    algo::is_cyclic_directed,
    graph::{Graph, NodeIndex},
    prelude::EdgeRef,
    visit::{VisitMap, Visitable},
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

#[derive(Clone)]
pub struct AnalysisService {
    graph: Arc<RwLock<GraphMap>>,
}

/// Collect related nodes in the provided direction.
///
/// If the depth is zero, or the node was already processed, it will return [`None`], indicating
/// that the request was not processed.
fn collect(
    graph: &Graph<PackageNode, Relationship, petgraph::Directed>,
    node: NodeIndex,
    direction: Direction,
    depth: u64,
    discovered: &mut FixedBitSet,
) -> Option<Vec<Node>> {
    log::debug!("Direction: {direction:?}");

    if depth == 0 {
        log::debug!("depth is zero");
        // we ran out of depth
        return None;
    }

    if !discovered.visit(node) {
        log::debug!("node got visited already");
        // we've already seen this
        return None;
    }

    let mut result = Vec::new();

    for edge in graph.edges_directed(node, direction) {
        let relationship = edge.weight();
        let neighbor = edge.target();

        let Some(package_node) = graph.node_weight(neighbor) else {
            continue;
        };

        let related = collect(graph, neighbor, direction, depth - 1, discovered);
        // we only recurse in one direction
        let (ancestor, descendent) = match direction {
            Direction::Incoming => (related, None),
            Direction::Outgoing => (None, related),
        };

        result.push(Node {
            base: BaseSummary::from(package_node),
            relationship: Some(*relationship),
            ancestor,
            descendent,
        });
    }

    Some(result)
}

impl AnalysisService {
    /// Create a new analysis service instance.
    ///
    /// ## Caching
    ///
    /// A new instance will have a new cache. Instanced cloned from it, will share that cache.
    ///
    /// Therefore, it is ok to create a new instance. However, if you want to make use of the
    /// caching, it is necessary to re-use that instance.
    ///
    /// Also, we do not implement default because of this. As a new instance has the implication
    /// of having its own cache. So creating a new instance should be a deliberate choice.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            graph: Default::default(),
        }
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
    /// Similar to [`Self::query_graphs`], but manages the state of collecting.
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
        C: Fn(&mut T, &Graph<PackageNode, Relationship>, NodeIndex, &PackageNode, &mut FixedBitSet),
    {
        let mut value = init();

        self.query_graphs(
            query,
            distinct_sbom_ids,
            |graph, index, node, discovered| {
                collector(&mut value, graph, index, node, discovered);
            },
        );

        value
    }

    /// Traverse the graph, call the function for every matching node.
    #[instrument(skip(self, f))]
    fn query_graphs<'a, F>(
        &self,
        query: impl Into<GraphQuery<'a>> + Debug,
        distinct_sbom_ids: Vec<String>,
        mut f: F,
    ) where
        F: FnMut(&Graph<PackageNode, Relationship>, NodeIndex, &PackageNode, &mut FixedBitSet),
    {
        let query = query.into();

        // RwLock for reading hashmap<graph>
        let graph_read_guard = self.graph.read();
        for distinct_sbom_id in &distinct_sbom_ids {
            self.query_graph(&graph_read_guard, query, distinct_sbom_id, &mut f);
        }
    }

    #[instrument(skip(self, graph, f))]
    fn query_graph<F>(&self, graph: &GraphMap, query: GraphQuery<'_>, sbom_id: &str, f: &mut F)
    where
        F: FnMut(&Graph<PackageNode, Relationship>, NodeIndex, &PackageNode, &mut FixedBitSet),
    {
        let Some(graph) = graph.get(sbom_id) else {
            log::warn!("Unable to find SBOM: {sbom_id}");
            return;
        };

        if is_cyclic_directed(graph) {
            log::warn!(
                "analysis graph of sbom {} has circular references!",
                sbom_id
            );
            return;
        }

        let mut visited = HashSet::new();
        let mut discovered = graph.visit_map();

        // Iterate over matching node indices and process them directly
        graph
            .node_indices()
            .filter(|&i| Self::filter(graph, &query, i))
            .for_each(|node_index| {
                log::debug!("matched!");
                if visited.insert(node_index) {
                    if let Some(find_match_package_node) = graph.node_weight(node_index) {
                        f(graph, node_index, find_match_package_node, &mut discovered);
                    }
                }
            });
    }

    #[instrument(skip(self))]
    pub fn run_graph_query<'a>(
        &self,
        query: impl Into<GraphQuery<'a>> + Debug,
        options: QueryOptions,
        distinct_sbom_ids: Vec<String>,
    ) -> Vec<Node> {
        self.collect_graph(
            query,
            distinct_sbom_ids,
            Vec::new,
            |components, graph, node_index, node, _| {
                log::debug!(
                    "Discovered node - sbom: {}, node: {}",
                    node.sbom_id,
                    node.node_id
                );
                components.push(Node {
                    base: node.into(),
                    relationship: None,
                    ancestor: collect(
                        graph,
                        node_index,
                        Direction::Incoming,
                        options.ancestors,
                        &mut graph.visit_map(),
                    ),
                    descendent: collect(
                        graph,
                        node_index,
                        Direction::Outgoing,
                        options.descendants,
                        &mut graph.visit_map(),
                    ),
                });
            },
        )
    }

    /// This function searches for a component(s) by name in a specific sbom, then returns that
    /// component's root components.
    pub async fn retrieve_all_sbom_roots_by_name<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        component_name: String,
        connection: &C,
    ) -> Result<Vec<Node>, Error> {
        let distinct_sbom_ids = vec![sbom_id.to_string()];
        self.load_graphs(connection, &distinct_sbom_ids).await?;

        let components = self.run_graph_query(
            GraphQuery::Component(ComponentReference::Name(&component_name)),
            QueryOptions::ancestors(),
            distinct_sbom_ids,
        );

        Ok(components.roots())
    }

    /// locate components, retrieve dependency information
    #[instrument(skip(self, connection), err)]
    pub async fn retrieve<C: ConnectionTrait>(
        &self,
        query: impl Into<GraphQuery<'_>> + Debug,
        options: impl Into<QueryOptions> + Debug,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<Node>, Error> {
        let query = query.into();
        let options = options.into();

        let distinct_sbom_ids = self.load_graphs_query(connection, query).await?;
        let components = self.run_graph_query(query, options, distinct_sbom_ids);

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
