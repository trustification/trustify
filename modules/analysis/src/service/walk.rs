use super::*;

/// A visitor for a graph nodes.
///
/// The visitor is called for each node and each edge, in no particular order. Finally, it is
/// guaranteed to have [`Self::complete`] called exactly once. Unless the graph was not found or
/// an error occurred.
///
/// **Note:** It may be that nodes are actually from multiple SBOMs. Each node will have an SBOM ID,
/// which identifies the SBOM the node belongs to.
pub trait Visitor {
    type Output;

    fn node(&mut self, node: &PackageNode);
    fn edge(&mut self, source: &PackageNode, relationship: Relationship, target: &PackageNode);

    fn complete(self) -> Self::Output;
}

impl AnalysisService {
    /// Walk the graph of an SBOM.
    ///
    /// This will look up the SBOM, but not load it.
    ///
    /// If the SBOM was not found, then [`None`] will be returned.
    ///
    /// Otherwise, the visitor will be called, and it will return the output of the
    /// [`Visitor::complete`] function.
    pub fn walk<V>(&self, sbom: &str, mut v: V) -> Option<V::Output>
    where
        V: Visitor,
    {
        let graph = self.graph.read();
        let graph = graph.get(sbom)?;

        for node in graph.node_weights() {
            v.node(node);
        }

        for edge in graph.raw_edges() {
            let source = graph.node_weight(edge.source());
            let target = graph.node_weight(edge.target());

            if let (Some(source), Some(target)) = (source, target) {
                v.edge(source, edge.weight, target);
            }
        }

        Some(v.complete())
    }
}
