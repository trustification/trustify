use super::*;
use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc};

/// Tracker for visited nodes, across graphs.
#[derive(Default, Clone)]
pub struct DiscoveredTracker {
    cache: Arc<Mutex<HashMap<*const NodeGraph, FixedBitSet>>>,
}

impl DiscoveredTracker {
    pub fn visit(&self, graph: &NodeGraph, node: NodeIndex) -> bool {
        let mut maps = self.cache.lock();
        let map = maps
            .entry(graph as *const Graph<_, _>)
            .or_insert_with(|| graph.visit_map());

        map.visit(node)
    }
}

/// Collector, helping on collector nodes from a graph.
///
/// Keeping track of all relevant information.
pub struct Collector<'a, C: ConnectionTrait> {
    graph_cache: &'a Arc<GraphMap>,
    graphs: &'a [(String, Arc<PackageGraph>)],
    graph: &'a NodeGraph,
    node: NodeIndex,
    direction: Direction,
    depth: u64,
    discovered: DiscoveredTracker,
    relationships: &'a HashSet<Relationship>,
    connection: &'a C,
}

impl<'a, C: ConnectionTrait> Collector<'a, C> {
    /// Create a new collector, with a new visited set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        graph_cache: &'a Arc<GraphMap>,
        graphs: &'a [(String, Arc<PackageGraph>)],
        graph: &'a NodeGraph,
        node: NodeIndex,
        direction: Direction,
        depth: u64,
        relationships: &'a HashSet<Relationship>,
        connection: &'a C,
    ) -> Self {
        Self {
            graph_cache,
            graphs,
            graph,
            node,
            direction,
            depth,
            discovered: Default::default(),
            relationships,
            connection,
        }
    }

    /// Continue with another graph and node as an entry point.
    ///
    /// Shares the visited set.
    pub fn with(self, graph: &'a NodeGraph, node: NodeIndex) -> Self {
        Self {
            graph,
            node,
            ..self
        }
    }

    /// Continue with a new node, but the same graph.
    ///
    /// Decreases depth by one and keeps the visited set.
    pub fn continue_node(&self, node: NodeIndex) -> Self {
        Self {
            graph_cache: self.graph_cache,
            graphs: self.graphs,
            graph: self.graph,
            node,
            direction: self.direction,
            depth: self.depth - 1,
            discovered: self.discovered.clone(),
            relationships: self.relationships,
            connection: self.connection,
        }
    }

    /// Collect related nodes in the provided direction.
    ///
    /// If the depth is zero, or the node was already processed, it will return [`None`], indicating
    /// that the request was not processed.
    pub async fn collect(self) -> Option<Vec<Node>> {
        tracing::debug!(direction = ?self.direction, "collecting for {:?}", self.node);

        if self.depth == 0 {
            log::debug!("depth is zero");
            // we ran out of depth
            return None;
        }

        if !self.discovered.visit(self.graph, self.node) {
            log::debug!("node got visited already");
            // we've already seen this
            return None;
        }

        match self.graph.node_weight(self.node) {
            // collect external sbom ref
            Some(graph::Node::External(external_node)) => {
                let ResolvedSbom {
                    sbom_id: external_sbom_id,
                    node_id: external_node_id,
                } = resolve_external_sbom(external_node.node_id.clone(), self.connection).await?;

                log::debug!("external sbom id: {:?}", external_sbom_id);
                log::debug!("external node id: {:?}", external_node_id);

                // get external sbom graph from graph_cache
                // TODO: decide if we use graph_cache as illustrated
                let Some(external_graph) = self.graph_cache.get(&external_sbom_id.to_string())
                else {
                    log::warn!("Graph not found.");
                    return None;
                };
                // now that we have the graph, find the external node reference in that graph
                // so we have a starting point.
                let Some(external_node_index) = external_graph
                    .node_indices()
                    .find(|&node| external_graph[node].node_id.eq(&external_node_id))
                else {
                    log::warn!("Node with ID {} not found", external_node_id);
                    // You can return early, log an error, or take other actions as needed
                    return None;
                };

                // process as normal, which is just non-DRY of following code block which we
                // can optimise away.
                log::debug!("external node index: {:?}", external_node_index);
                log::debug!("external graph {:?}", external_graph);

                Some(
                    self.with(external_graph.as_ref(), external_node_index)
                        .collect_graph()
                        .await,
                )
            }
            // collect
            _ => Some(self.collect_graph().await),
        }
    }

    pub async fn collect_graph(&self) -> Vec<Node> {
        let mut result = vec![];
        log::debug!("Collecting graph for {:?}", self.node);
        for edge in self.graph.edges_directed(self.node, self.direction) {
            log::debug!("edge {edge:?}");

            // we only recurse in one direction
            let (ancestor, descendent, package_node) = match self.direction {
                Direction::Incoming => (
                    Box::pin(self.continue_node(edge.source()).collect()).await,
                    None,
                    self.graph.node_weight(edge.source()),
                ),
                Direction::Outgoing => (
                    None,
                    Box::pin(self.continue_node(edge.target()).collect()).await,
                    self.graph.node_weight(edge.target()),
                ),
            };

            let relationship = edge.weight();

            if !self.relationships.is_empty() && !self.relationships.contains(relationship) {
                // if we have entries, and no match, continue with the next
                continue;
            }

            let Some(package_node) = package_node else {
                continue;
            };

            result.push(Node {
                base: BaseSummary::from(package_node),
                relationship: Some(*relationship),
                ancestors: ancestor,
                descendants: descendent,
            });
        }

        result
    }
}
