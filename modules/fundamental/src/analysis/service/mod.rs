use crate::Error;
use sea_orm::{prelude::ConnectionTrait, Statement};
use std::collections::HashMap;
use tracing::instrument;
use trustify_common::{
    db::{query::Query, Database, Transactional},
    model::{Paginated, PaginatedResults},
};

use petgraph::graph::{Graph, NodeIndex};
// use petgraph::visit::EdgeRef;
use petgraph::Direction;
use regex::Regex;
use serde::Serialize;
use std::fmt;
use std::str::FromStr;
use trustify_common::purl::Purl;
use trustify_entity::relationship::Relationship;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct PackageNode {
    purl: String,
    name: String,
    published: String,
    document_id: String,
    product_name: String,
    product_version: String,
}
impl fmt::Display for PackageNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AdvisoryGraphSummary {
    pub component: String,
    pub ancestors: Vec<PackageNode>,
}
impl AdvisoryGraphSummary {
    fn new(component: String, ancestors: Vec<PackageNode>) -> AdvisoryGraphSummary {
        AdvisoryGraphSummary {
            component,
            ancestors,
        }
    }
}

pub struct AnalysisService {
    db: Database,
}

#[allow(clippy::too_many_arguments)]
pub fn add_node(
    g: &mut Graph<PackageNode, Relationship, petgraph::Directed>,
    nodes: &mut HashMap<String, NodeIndex>,
    component_purl: &String,
    component_name: &String,
    sbom_published: &String,
    document_id: &String,
    product_name: &String,
    product_version: &String,
) -> NodeIndex {
    match nodes.get(&component_purl.to_string()) {
        Some(&i) => i,
        None => {
            let i = g.add_node(PackageNode {
                purl: component_purl.to_string(),
                name: component_name.to_string(),
                published: sbom_published.to_string(),
                document_id: document_id.to_string(),
                product_name: product_name.to_string(),
                product_version: product_version.to_string(),
            });
            nodes.insert(component_purl.to_string(), i);
            i
        }
    }
}

pub fn regex_purl_find(nodes: &HashMap<String, NodeIndex>, search_value: &str) -> Vec<NodeIndex> {
    // Sanitize the search value to prevent regex injection attacks
    let sanitized_search_value = regex::escape(search_value);

    let pattern = match Regex::new(&sanitized_search_value) {
        Ok(pattern) => pattern,
        Err(_) => return Vec::new(), // Return an empty vector if the regex pattern is invalid
    };

    nodes
        .iter()
        .filter(|(key, _)| pattern.is_match(key))
        .map(|(_, value)| *value)
        .collect()
}

pub fn exact_name_find(nodes: &HashMap<String, NodeIndex>, search_value: &str) -> Vec<NodeIndex> {
    nodes
        .iter()
        .filter_map(|(key, &value)| {
            Purl::from_str(key).ok().and_then(|purl| {
                if purl.name == search_value {
                    Some(value)
                } else {
                    None
                }
            })
        })
        .collect()
}

pub fn ancestor_nodes(
    graph: &petgraph::Graph<PackageNode, Relationship, petgraph::Directed>,
    node: NodeIndex,
    original_node: NodeIndex,
) -> Vec<NodeIndex> {
    // we need order
    let mut ancestor_nodes: Vec<NodeIndex> = Vec::new();
    if node != original_node {
        ancestor_nodes.push(node);
    }
    fn dfs(
        graph: &petgraph::Graph<PackageNode, Relationship, petgraph::Directed>,
        node: NodeIndex,
        original_node: NodeIndex,
        ancestor_nodes: &mut Vec<NodeIndex>,
    ) {
        for neighbor in graph.neighbors_directed(node, Direction::Outgoing) {
            if neighbor == original_node {
                break; // no need to descend further past the original node in the tree
            }
            if !ancestor_nodes.contains(&neighbor) {
                ancestor_nodes.push(neighbor);
                dfs(graph, neighbor, original_node, ancestor_nodes);
            }
        }
    }
    dfs(graph, node, original_node, &mut ancestor_nodes);
    ancestor_nodes
}

impl AnalysisService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    #[allow(clippy::match_single_binding)]
    #[instrument(skip(self, tx), err)]
    pub async fn retrieve_root_components<TX: AsRef<Transactional>>(
        &self,
        query: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<AdvisoryGraphSummary>, Error> {
        let connection = self.db.connection(&tx);
        let mut g: Graph<PackageNode, Relationship, petgraph::Directed> = Graph::new();
        log::info!("step 1");

        // TODO: convert this to 'sea_orm dialect'
        let sql = format!(
            r#"SELECT sbom.document_id, sbom.sbom_id, sbom.published::text,
            get_purl(t1.qualified_purl_id) as left_qualified_purl,
            package_relates_to_package.relationship,
            get_purl(t2.qualified_purl_id) as right_qualified_purl,
            product.name as product_name,
            product_version.version as product_version
            FROM sbom
            LEFT JOIN product_version ON sbom.sbom_id = product_version.sbom_id
            LEFT JOIN product ON product_version.product_id = product.id
            LEFT JOIN package_relates_to_package ON sbom.sbom_id = package_relates_to_package.sbom_id
            LEFT JOIN sbom_package_purl_ref t1 ON t1.sbom_id = sbom.sbom_id AND t1.node_id = package_relates_to_package.left_node_id
            LEFT JOIN sbom_package_purl_ref t2 ON t2.sbom_id = sbom.sbom_id AND t2.node_id = package_relates_to_package.right_node_id
            WHERE package_relates_to_package.relationship IN (0,8,14)
                AND sbom.sbom_id IN (SELECT DISTINCT ON (document_id) sbom_id FROM sbom WHERE sbom.sbom_id IN (select distinct sbom_id from sbom_node where name ILIKE '%{}%')
                order by document_id, published DESC);
             "#,
            query.q.as_str()
        );

        let relationship_results = connection
            .query_all(Statement::from_string(
                connection.get_database_backend(),
                sql,
            ))
            .await?;

        log::info!("step 2:{}", relationship_results.len());

        // keep track of nodes / indices for efficient searching
        let mut nodes: HashMap<String, NodeIndex> = HashMap::new();

        // load package relationships into graph
        for row in relationship_results {
            let sbom_published = row
                .try_get("", "published")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let document_id = row
                .try_get("", "document_id")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let product_name = row
                .try_get("", "product_name")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let product_version = row
                .try_get("", "product_version")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right

            let left_purl_string: String = row
                .try_get("", "left_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let left_purl: Purl = Purl::from_str(left_purl_string.as_str())?;
            let p1 = add_node(
                &mut g,
                &mut nodes,
                &left_purl_string,
                &left_purl.name,
                &sbom_published,
                &document_id,
                &product_name,
                &product_version,
            );

            let relationship: Relationship = row.try_get("", "relationship")?;
            let right_purl_string: String = row
                .try_get("", "right_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let right_purl: Purl = Purl::from_str(right_purl_string.as_str())?;
            let p2 = add_node(
                &mut g,
                &mut nodes,
                &right_purl_string,
                &right_purl.name,
                &sbom_published,
                &document_id,
                &product_name,
                &product_version,
            );

            g.add_edge(p1, p2, relationship);
        }

        log::info!("step 3: {}", g.node_count());

        let mut components: Vec<AdvisoryGraphSummary> = Vec::new();

        for node_index in regex_purl_find(&nodes, query.q.as_str()) {
            if let Some(find_match_package_node) = g.node_weight(node_index) {
                let mut ancestor_nodes: Vec<NodeIndex> = ancestor_nodes(&g, node_index, node_index)
                    .into_iter()
                    .collect();

                ancestor_nodes.sort();

                let mut root_components: Vec<PackageNode> = ancestor_nodes
                    .iter()
                    .filter_map(|&ancestor_node| g.node_weight(ancestor_node).cloned())
                    .collect();

                root_components.sort_by(|a, b| a.published.cmp(&b.published));

                components.push(AdvisoryGraphSummary::new(
                    find_match_package_node.purl.to_string(),
                    root_components,
                ));
            }
        }
        log::info!("step 4");

        // TODO: limiter ?
        let total: u64 = components.len() as u64;
        Ok(PaginatedResults {
            items: components,
            total,
        })
    }

    #[allow(clippy::match_single_binding)]
    #[instrument(skip(self, tx), err)]
    pub async fn retrieve_root_components_by_name<TX: AsRef<Transactional>>(
        &self,
        component_name: String,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<AdvisoryGraphSummary>, Error> {
        let connection = self.db.connection(&tx);
        let mut g: Graph<PackageNode, Relationship, petgraph::Directed> = Graph::new();

        // TODO: convert this to 'sea_orm dialect'
        let sql = format!(
            r#"SELECT sbom.document_id, sbom.sbom_id, sbom.published::text,
             get_purl(t1.qualified_purl_id) as left_qualified_purl,
             package_relates_to_package.relationship,
             get_purl(t2.qualified_purl_id) as right_qualified_purl,
             product.name as product_name,
             product_version.version as product_version
             FROM sbom
             LEFT JOIN product_version ON sbom.sbom_id = product_version.sbom_id
             LEFT JOIN product ON product_version.product_id = product.id
             LEFT JOIN package_relates_to_package ON sbom.sbom_id = package_relates_to_package.sbom_id
             LEFT JOIN sbom_package_purl_ref t1 ON t1.sbom_id = sbom.sbom_id AND t1.node_id = package_relates_to_package.left_node_id
             LEFT JOIN sbom_package_purl_ref t2 ON t2.sbom_id = sbom.sbom_id AND t2.node_id = package_relates_to_package.right_node_id
             WHERE package_relates_to_package.relationship IN (0,8,14)
             AND sbom.sbom_id IN (SELECT DISTINCT ON (document_id) sbom_id FROM sbom where sbom.sbom_id IN (select
  distinct sbom_id from sbom_node where name = '{}') order by document_id, published DESC);
             "#,
            component_name.as_str()
        );

        let results = connection
            .query_all(Statement::from_string(
                connection.get_database_backend(),
                sql,
            ))
            .await?;

        // Create HashMap to keep track of nodes / indices for efficient loading
        let mut nodes: HashMap<String, NodeIndex> = HashMap::new();

        // load package relationships into graph
        for row in results {
            let sbom_published = row
                .try_get("", "published")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let document_id = row
                .try_get("", "document_id")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let product_name = row
                .try_get("", "product_name")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let product_version = row
                .try_get("", "product_version")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right

            let left_purl_string: String = row
                .try_get("", "left_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let left_purl: Purl = Purl::from_str(left_purl_string.as_str())?;
            let p1 = add_node(
                &mut g,
                &mut nodes,
                &left_purl_string,
                &left_purl.name,
                &sbom_published,
                &document_id,
                &product_name,
                &product_version,
            );

            let relationship: Relationship = row.try_get("", "relationship")?;

            let right_purl_string: String = row
                .try_get("", "right_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let right_purl: Purl = Purl::from_str(right_purl_string.as_str())?;
            let p2 = add_node(
                &mut g,
                &mut nodes,
                &right_purl_string,
                &right_purl.name,
                &sbom_published,
                &document_id,
                &product_name,
                &product_version,
            );

            g.add_edge(p1, p2, relationship);
        }

        let mut components: Vec<AdvisoryGraphSummary> = Vec::new();

        for node_index in exact_name_find(&nodes, component_name.as_str()) {
            if let Some(find_match_package_node) = g.node_weight(node_index) {
                let mut ancestor_nodes: Vec<NodeIndex> = ancestor_nodes(&g, node_index, node_index)
                    .into_iter()
                    .collect();

                ancestor_nodes.sort();

                let mut root_components: Vec<PackageNode> = ancestor_nodes
                    .iter()
                    .filter_map(|&ancestor_node| g.node_weight(ancestor_node).cloned())
                    .collect();

                root_components.sort_by(|a, b| a.published.cmp(&b.published));

                components.push(AdvisoryGraphSummary::new(
                    find_match_package_node.purl.to_string(),
                    root_components,
                ));
            }
        }

        // TODO: limiter ?
        let total: u64 = components.len() as u64;
        Ok(PaginatedResults {
            items: components,
            total,
        })
    }

    #[allow(clippy::match_single_binding)]
    #[instrument(skip(self, tx), err)]
    pub async fn retrieve_root_components_by_purl<TX: AsRef<Transactional>>(
        &self,
        component_purl: Purl,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<AdvisoryGraphSummary>, Error> {
        let connection = self.db.connection(&tx);
        let mut g: Graph<PackageNode, Relationship, petgraph::Directed> = Graph::new();

        // TODO: convert this to 'sea_orm dialect'
        let sql = format!(
            r#"SELECT sbom.document_id, sbom.sbom_id, sbom.published::text,
            get_purl(t1.qualified_purl_id) as left_qualified_purl,
            package_relates_to_package.relationship,
            get_purl(t2.qualified_purl_id) as right_qualified_purl,
            product.name as product_name,
            product_version.version as product_version
            FROM sbom
            LEFT JOIN product_version ON sbom.sbom_id = product_version.sbom_id
            LEFT JOIN product ON product_version.product_id = product.id
            LEFT JOIN package_relates_to_package ON sbom.sbom_id = package_relates_to_package.sbom_id
            LEFT JOIN sbom_package_purl_ref t1 ON t1.sbom_id = sbom.sbom_id AND t1.node_id = package_relates_to_package.left_node_id
            LEFT JOIN sbom_package_purl_ref t2 ON t2.sbom_id = sbom.sbom_id AND t2.node_id = package_relates_to_package.right_node_id
            WHERE package_relates_to_package.relationship IN (0,8,14)
                AND sbom.sbom_id IN (SELECT DISTINCT ON (document_id) sbom_id FROM sbom where sbom.sbom_id IN (select distinct sbom_id from sbom_node where name = '{}')
                order by document_id, published DESC);
             "#,
            component_purl.name
        );

        let results = connection
            .query_all(Statement::from_string(
                connection.get_database_backend(),
                sql,
            ))
            .await?;

        // Create HashMap to keep track of nodes / indices for efficient loading
        let mut nodes: HashMap<String, NodeIndex> = HashMap::new();

        // load package relationships into graph
        for row in results {
            let sbom_published = row
                .try_get("", "published")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let document_id = row
                .try_get("", "document_id")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let product_name = row
                .try_get("", "product_name")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let product_version = row
                .try_get("", "product_version")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right

            let left_purl_string: String = row
                .try_get("", "left_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let left_purl: Purl = Purl::from_str(left_purl_string.as_str())?;
            let p1 = add_node(
                &mut g,
                &mut nodes,
                &left_purl_string,
                &left_purl.name,
                &sbom_published,
                &document_id,
                &product_name,
                &product_version,
            );

            let relationship: Relationship = row.try_get("", "relationship")?;

            let right_purl_string: String = row
                .try_get("", "right_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let right_purl: Purl = Purl::from_str(right_purl_string.as_str())?;
            let p2 = add_node(
                &mut g,
                &mut nodes,
                &right_purl_string,
                &right_purl.name,
                &sbom_published,
                &document_id,
                &product_name,
                &product_version,
            );

            g.add_edge(p1, p2, relationship);
        }

        let mut components: Vec<AdvisoryGraphSummary> = Vec::new();

        for node_index in regex_purl_find(&nodes, component_purl.to_string().as_str()) {
            if let Some(find_match_package_node) = g.node_weight(node_index) {
                let mut ancestor_nodes: Vec<NodeIndex> = ancestor_nodes(&g, node_index, node_index)
                    .into_iter()
                    .collect();

                ancestor_nodes.sort();

                let mut root_components: Vec<PackageNode> = ancestor_nodes
                    .iter()
                    .filter_map(|&ancestor_node| g.node_weight(ancestor_node).cloned())
                    .collect();

                root_components.sort_by(|a, b| a.published.cmp(&b.published));

                components.push(AdvisoryGraphSummary::new(
                    find_match_package_node.purl.to_string(),
                    root_components,
                ));
            }
        }

        // TODO: limiter ?
        let total: u64 = components.len() as u64;
        Ok(PaginatedResults {
            items: components,
            total,
        })
    }
}

#[cfg(test)]
mod test;
