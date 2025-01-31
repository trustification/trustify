use petgraph::Graph;
use serde::Serialize;
use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use moka::sync::Cache;
use std::sync::Arc;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::relationship::Relationship;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct AnalysisStatus {
    /// The number of SBOMs found in the database
    pub sbom_count: u32,
    /// The number of graphs loaded in memory
    pub graph_count: u32,
}

impl fmt::Display for AnalysisStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "graph_count {}", self.graph_count)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct PackageNode {
    pub sbom_id: String,
    pub node_id: String,
    pub purl: Vec<Purl>,
    pub cpe: Vec<Cpe>,
    pub name: String,
    pub version: String,
    pub published: String,
    pub document_id: String,
    pub product_name: String,
    pub product_version: String,
    pub approximate_memory_size: u32,
}

impl PackageNode {
    pub(crate) fn set_approximate_memory_size(&self) -> PackageNode {
        // Is there a better way to do this?
        let size = size_of::<PackageNode>()
            + self.sbom_id.len()
            + self.node_id.len()
            + self.purl.iter().fold(0, |acc, purl|
                // use the json string length as an approximation of the memory size
                acc + serde_json::to_string(purl).unwrap_or_else(|_| "".to_string()).len())
            + self.cpe.iter().fold(0, |acc, cpe|
                // use the json string length as an approximation of the memory size
                acc + serde_json::to_string(cpe).unwrap_or_else(|_| "".to_string()).len())
            + self.name.len()
            + self.version.len()
            + self.published.len()
            + self.document_id.len()
            + self.product_name.len()
            + self.product_version.len();

        PackageNode {
            approximate_memory_size: size.try_into().unwrap_or(u32::MAX),
            ..self.clone()
        }
    }
}

impl fmt::Display for PackageNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.purl)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct AncNode {
    pub sbom_id: String,
    pub node_id: String,
    pub relationship: String,
    pub purl: Vec<Purl>,
    pub cpe: Vec<Cpe>,
    pub name: String,
    pub version: String,
}

impl fmt::Display for AncNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.purl)
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BaseSummary {
    pub sbom_id: String,
    pub node_id: String,
    pub purl: Vec<Purl>,
    pub cpe: Vec<Cpe>,
    pub name: String,
    pub version: String,
    pub published: String,
    pub document_id: String,
    pub product_name: String,
    pub product_version: String,
}

impl From<&PackageNode> for BaseSummary {
    fn from(value: &PackageNode) -> Self {
        Self {
            sbom_id: value.sbom_id.to_string(),
            node_id: value.node_id.to_string(),
            purl: value.purl.clone(),
            cpe: value.cpe.clone(),
            name: value.name.to_string(),
            version: value.version.to_string(),
            published: value.published.to_string(),
            document_id: value.document_id.to_string(),
            product_name: value.product_name.to_string(),
            product_version: value.product_version.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AncestorSummary {
    #[serde(flatten)]
    pub base: BaseSummary,
    pub ancestors: Vec<AncNode>,
}

impl Deref for AncestorSummary {
    type Target = BaseSummary;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for AncestorSummary {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct DepNode {
    pub sbom_id: String,
    pub node_id: String,
    pub relationship: String,
    pub purl: Vec<Purl>,
    pub cpe: Vec<Cpe>,
    pub name: String,
    pub version: String,
    #[schema(no_recursion)]
    pub deps: Vec<DepNode>,
}

impl fmt::Display for DepNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.purl)
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DepSummary {
    #[serde(flatten)]
    pub base: BaseSummary,
    pub deps: Vec<DepNode>,
}

impl Deref for DepSummary {
    type Target = BaseSummary;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for DepSummary {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

pub type PackageGraph = Graph<PackageNode, Relationship, petgraph::Directed>;

pub struct GraphMap {
    map: Cache<String, Arc<PackageGraph>>,
}

#[allow(clippy::ptr_arg)] // &String is required by Cache::builder().weigher() method
fn weigher(key: &String, value: &Arc<PackageGraph>) -> u32 {
    let mut result = key.len();
    for n in value.raw_nodes() {
        result += n.weight.approximate_memory_size as usize;
    }
    result += size_of_val(value.raw_edges());
    result.try_into().unwrap_or(u32::MAX)
}

impl GraphMap {
    // Create a new instance of GraphMap
    pub fn new(cap: u64) -> Self {
        GraphMap {
            map: Cache::builder().weigher(weigher).max_capacity(cap).build(),
        }
    }

    // Check if the map contains a key
    pub fn contains_key(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    // Get the number of graphs in the map
    pub fn len(&self) -> u64 {
        self.map.entry_count()
    }

    // Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn size_used(&self) -> u64 {
        self.map.weighted_size()
    }

    // Add a new graph with the given key (write access)
    pub fn insert(&self, key: String, graph: Arc<PackageGraph>) {
        self.map.insert(key, graph);
        self.map.run_pending_tasks();
    }

    // Retrieve a reference to a graph by its key (read access)
    pub fn get(&self, key: &str) -> Option<Arc<PackageGraph>> {
        self.map.get(key)
    }

    // Clear all graphs from the map
    pub fn clear(&self) {
        self.map.invalidate_all();
        self.map.run_pending_tasks();
    }
}
