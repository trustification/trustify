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

pub fn add_node(
    g: &mut Graph<PackageNode, Relationship, petgraph::Directed>,
    nodes: &mut HashMap<String, NodeIndex>,
    component_purl: String,
    component_name: String,
    sbom_published: String,
) -> NodeIndex {
    match nodes.get(&component_purl) {
        Some(&i) => i,
        None => {
            let i = g.add_node(PackageNode {
                purl: component_purl.to_string(),
                name: component_name.to_string(),
                published: sbom_published.to_string(),
            });
            nodes.insert(component_purl, i);
            i
        }
    }
}

pub fn regex_purl_find(nodes: &HashMap<String, NodeIndex>, search_value: &str) -> Vec<NodeIndex> {
    let pattern = Regex::new(search_value).unwrap(); // TODO: needs sanitisation
    let mut node_indexes = Vec::new();
    for (key, value) in nodes.iter() {
        if pattern.is_match(key) {
            node_indexes.push(*value);
        }
    }
    node_indexes
}

pub fn exact_name_find(nodes: &HashMap<String, NodeIndex>, search_value: &str) -> Vec<NodeIndex> {
    let mut node_indexes = Vec::new();
    for (key, value) in nodes.iter() {
        let purl_name = Purl::from_str(key).unwrap().name;
        if search_value.eq(purl_name.as_str()) {
            node_indexes.push(*value);
        }
    }
    node_indexes
}

pub fn ancestor_nodes(
    graph: &petgraph::Graph<PackageNode, Relationship, petgraph::Directed>,
    node: NodeIndex,
    original_node: NodeIndex,
) -> Vec<NodeIndex> {
    // we need order
    let mut ancestor_nodes: Vec<NodeIndex> = Vec::new();
    ancestor_nodes.push(node);
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

    #[instrument(skip(self, tx), err)]
    pub async fn retrieve_root_components<TX: AsRef<Transactional>>(
        &self,
        query: Query,
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
            get_purl(t2.qualified_purl_id) as right_qualified_purl
            FROM sbom
            LEFT JOIN package_relates_to_package ON sbom.sbom_id = package_relates_to_package.sbom_id
            LEFT JOIN sbom_package_purl_ref t1 ON t1.sbom_id = sbom.sbom_id AND t1.node_id = package_relates_to_package.left_node_id
            LEFT JOIN sbom_package_purl_ref t2 ON t2.sbom_id = sbom.sbom_id AND t2.node_id = package_relates_to_package.right_node_id
            WHERE package_relates_to_package.relationship IN (0,8,14)
                AND sbom.sbom_id IN (SELECT DISTINCT ON (document_id) sbom_id FROM sbom order by document_id, published DESC)
                AND sbom.sbom_id IN (select distinct sbom_id from sbom_node where name ILIKE '%{}%');
             "#,
            query.q.as_str()
        );

        let results = connection
            .query_all(Statement::from_string(
                connection.get_database_backend(),
                sql,
            ))
            .await?;

        // keep track of nodes / indices for efficient searching
        let mut nodes: HashMap<String, NodeIndex> = HashMap::new();

        // load package relationships into graph
        for row in results {
            let sbom_published = row
                .try_get("", "published")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right

            let left_purl_string: String = row
                .try_get("", "left_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let left_purl: Purl = Purl::from_str(left_purl_string.as_str())?;
            let left_name: String = left_purl.name;
            let p1 = add_node(
                &mut g,
                &mut nodes,
                left_purl_string.to_string(),
                left_name.to_string(),
                sbom_published.to_string(),
            );

            let relationship: Relationship = row.try_get("", "relationship")?;
            let right_purl_string: String = row
                .try_get("", "right_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let right_purl: Purl = Purl::from_str(right_purl_string.as_str())?;
            let right_name: String = right_purl.name;
            let p2 = add_node(
                &mut g,
                &mut nodes,
                right_purl_string.to_string(),
                right_name.to_string(),
                sbom_published.to_string(),
            );

            g.add_edge(p1, p2, relationship);
        }

        let mut components: Vec<AdvisoryGraphSummary> = Vec::new();
        for find_match in regex_purl_find(&nodes, query.q.as_str()) {
            let mut root_components: Vec<PackageNode> = Vec::new();

            match find_match {
                node_index => {
                    let find_match_package_node = g.node_weight(node_index).unwrap();
                    let mut ancestor_nodes: Vec<NodeIndex> =
                        ancestor_nodes(&g, node_index, node_index)
                            .into_iter()
                            .collect();
                    ancestor_nodes.sort();
                    for ancestor_node in ancestor_nodes {
                        let node_value = g.node_weight(ancestor_node).unwrap();
                        root_components.push(PackageNode {
                            purl: node_value.purl.to_string(),
                            name: node_value.name.to_string(),
                            published: node_value.published.to_string(),
                        });
                    }

                    components.push(AdvisoryGraphSummary::new(
                        find_match_package_node.purl.to_string(),
                        root_components,
                    ));
                }
            }
        }

        // TODO: limiter ?
        let total: u64 = components.len() as u64;
        Ok(PaginatedResults {
            items: components,
            total,
        })
    }

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
            get_purl(t2.qualified_purl_id) as right_qualified_purl
            FROM sbom
            LEFT JOIN package_relates_to_package ON sbom.sbom_id = package_relates_to_package.sbom_id
            LEFT JOIN sbom_package_purl_ref t1 ON t1.sbom_id = sbom.sbom_id AND t1.node_id = package_relates_to_package.left_node_id
            LEFT JOIN sbom_package_purl_ref t2 ON t2.sbom_id = sbom.sbom_id AND t2.node_id = package_relates_to_package.right_node_id
            WHERE package_relates_to_package.relationship IN (0,8,14)
                AND sbom.sbom_id IN (SELECT DISTINCT ON (document_id) sbom_id FROM sbom order by document_id, published DESC)
                AND sbom.sbom_id IN (select distinct sbom_id from sbom_node where name = '{}');
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

            let left_purl_string: String = row
                .try_get("", "left_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let left_purl: Purl = Purl::from_str(left_purl_string.as_str())?;
            let left_name: String = left_purl.name;
            let p1 = add_node(
                &mut g,
                &mut nodes,
                left_purl_string.to_string(),
                left_name.to_string(),
                sbom_published.to_string(),
            );

            let relationship: Relationship = row.try_get("", "relationship")?;

            let right_purl_string: String = row
                .try_get("", "right_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let right_purl: Purl = Purl::from_str(right_purl_string.as_str())?;
            let right_name: String = right_purl.name;
            let p2 = add_node(
                &mut g,
                &mut nodes,
                right_purl_string.to_string(),
                right_name.to_string(),
                sbom_published.to_string(),
            );

            g.add_edge(p1, p2, relationship);
        }

        let mut components: Vec<AdvisoryGraphSummary> = Vec::new();
        for find_match in exact_name_find(&nodes, component_name.as_str()) {
            let mut root_components: Vec<PackageNode> = Vec::new();

            match find_match {
                node_index => {
                    let find_match_package_node = g.node_weight(node_index).unwrap();
                    let mut ancestor_nodes: Vec<NodeIndex> =
                        ancestor_nodes(&g, node_index, node_index)
                            .into_iter()
                            .collect();
                    ancestor_nodes.sort();
                    for ancestor_node in ancestor_nodes {
                        let node_value = g.node_weight(ancestor_node).unwrap();
                        root_components.push(PackageNode {
                            purl: node_value.purl.to_string(),
                            name: node_value.name.to_string(),
                            published: node_value.published.to_string(),
                        });
                    }

                    components.push(AdvisoryGraphSummary::new(
                        find_match_package_node.purl.to_string(),
                        root_components,
                    ));
                }
            }
        }

        // TODO: limiter ?
        let total: u64 = components.len() as u64;
        Ok(PaginatedResults {
            items: components,
            total,
        })
    }

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
            get_purl(t2.qualified_purl_id) as right_qualified_purl
            FROM sbom
            LEFT JOIN package_relates_to_package ON sbom.sbom_id = package_relates_to_package.sbom_id
            LEFT JOIN sbom_package_purl_ref t1 ON t1.sbom_id = sbom.sbom_id AND t1.node_id = package_relates_to_package.left_node_id
            LEFT JOIN sbom_package_purl_ref t2 ON t2.sbom_id = sbom.sbom_id AND t2.node_id = package_relates_to_package.right_node_id
            WHERE package_relates_to_package.relationship IN (0,8,14)
                AND sbom.sbom_id IN (SELECT DISTINCT ON (document_id) sbom_id FROM sbom order by document_id, published DESC)
                AND sbom.sbom_id IN (select distinct sbom_id from sbom_node where name = '{}');
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

            let left_purl_string: String = row
                .try_get("", "left_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let left_purl: Purl = Purl::from_str(left_purl_string.as_str())?;
            let left_name: String = left_purl.name;
            let p1 = add_node(
                &mut g,
                &mut nodes,
                left_purl_string.to_string(),
                left_name.to_string(),
                sbom_published.to_string(),
            );

            let relationship: Relationship = row.try_get("", "relationship")?;

            let right_purl_string: String = row
                .try_get("", "right_qualified_purl")
                .unwrap_or("NOVALUE".to_string()); // TODO: this is not right
            let right_purl: Purl = Purl::from_str(right_purl_string.as_str())?;
            let right_name: String = right_purl.name;
            let p2 = add_node(
                &mut g,
                &mut nodes,
                right_purl_string.to_string(),
                right_name.to_string(),
                sbom_published.to_string(),
            );

            g.add_edge(p1, p2, relationship);
        }

        let mut components: Vec<AdvisoryGraphSummary> = Vec::new();
        for find_match in regex_purl_find(&nodes, component_purl.to_string().as_str()) {
            let mut root_components: Vec<PackageNode> = Vec::new();

            match find_match {
                node_index => {
                    let find_match_package_node = g.node_weight(node_index).unwrap();
                    let mut ancestor_nodes: Vec<NodeIndex> =
                        ancestor_nodes(&g, node_index, node_index)
                            .into_iter()
                            .collect();
                    ancestor_nodes.sort();
                    for ancestor_node in ancestor_nodes {
                        let node_value = g.node_weight(ancestor_node).unwrap();
                        root_components.push(PackageNode {
                            purl: node_value.purl.to_string(),
                            name: node_value.name.to_string(),
                            published: node_value.published.to_string(),
                        });
                    }

                    components.push(AdvisoryGraphSummary::new(
                        find_match_package_node.purl.to_string(),
                        root_components,
                    ));
                }
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
