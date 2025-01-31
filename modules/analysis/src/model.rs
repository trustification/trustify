mod roots;

pub use roots::*;

use petgraph::Graph;
use serde::Serialize;
use std::{
    fmt,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use deepsize::DeepSizeOf;
use moka::sync::Cache;
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

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize, DeepSizeOf)]
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
}

impl fmt::Display for PackageNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.purl)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Node {
    #[serde(flatten)]
    pub base: BaseSummary,

    /// The relationship the node has to it's containing node, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<Relationship>,

    /// All ancestors of this node. [`None`] if not requested on this level.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(no_recursion)]
    pub ancestors: Option<Vec<Node>>,

    /// All descendents of this node. [`None`] if not requested on this level.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(no_recursion)]
    pub descendants: Option<Vec<Node>>,
}

impl Deref for Node {
    type Target = BaseSummary;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for Node {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

pub type PackageGraph = Graph<PackageNode, Relationship, petgraph::Directed>;

pub struct GraphMap {
    map: Cache<String, Arc<PackageGraph>>,
}

#[allow(clippy::ptr_arg)] // &String is required by Cache::builder().weigher() method
fn size_of_graph_entry(key: &String, value: &Arc<PackageGraph>) -> u32 {
    (
        key.deep_size_of()
            + value.as_ref().deep_size_of()
            // Also add in some entry overhead of the cache entry
            + 20
        // todo: find a better estimate for the the moka ValueEntry
    )
    .try_into()
    .unwrap_or(u32::MAX)
}

impl GraphMap {
    // Create a new instance of GraphMap
    pub fn new(cap: u64) -> Self {
        GraphMap {
            map: Cache::builder()
                .weigher(size_of_graph_entry)
                .max_capacity(cap)
                .build(),
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
