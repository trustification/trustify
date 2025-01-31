use super::*;

pub trait Visitor {
    fn node(&mut self, node: &PackageNode);
    fn edge(&mut self, source: &PackageNode, relationship: Relationship, target: &PackageNode);
}

impl AnalysisService {
    pub fn walk<V>(&self, sbom: &str, mut v: V) -> bool
    where
        V: Visitor,
    {
        let graph = self.graph.read();
        let graph = graph.get(sbom);

        let Some(graph) = graph else {
            return false;
        };

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

        true
    }
}
