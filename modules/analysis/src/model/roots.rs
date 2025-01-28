use crate::model::Node;
use std::collections::HashMap;
use trustify_common::model::PaginatedResults;

pub trait Roots {
    /// Collect all top level ancestors.
    fn roots(self) -> Self;
}

impl Roots for PaginatedResults<Node> {
    fn roots(self) -> PaginatedResults<Node> {
        let items = self.items.roots();
        let total = items.len();
        Self {
            items,
            total: total as _,
        }
    }
}

impl Roots for Vec<Node> {
    fn roots(self) -> Vec<Node> {
        fn root_into(
            nodes: impl IntoIterator<Item = Node>,
            result: &mut HashMap<(String, String), Node>,
        ) {
            for node in nodes.into_iter() {
                root_into(node.ancestor.clone().into_iter().flatten(), result);

                if let Some(true) = node.ancestor.as_ref().map(|a| a.is_empty()) {
                    result.insert((node.base.sbom_id.clone(), node.base.node_id.clone()), node);
                }
            }
        }

        let mut result = HashMap::new();
        root_into(self, &mut result);

        result.into_values().collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::BaseSummary;
    use trustify_entity::relationship::Relationship;

    fn base(node_id: &str) -> BaseSummary {
        BaseSummary {
            sbom_id: "".to_string(),
            node_id: node_id.to_string(),
            purl: vec![],
            cpe: vec![],
            name: "".to_string(),
            version: "".to_string(),
            published: "".to_string(),
            document_id: "".to_string(),
            product_name: "".to_string(),
            product_version: "".to_string(),
        }
    }

    fn node(node_id: &str) -> Node {
        Node {
            base: base(node_id),
            relationship: None,
            ancestor: None,
            descendent: None,
        }
    }

    #[test]
    fn simple() {
        let result = vec![Node {
            base: base("AA"),
            relationship: None,
            ancestor: Some(vec![Node {
                ancestor: Some(vec![]),
                relationship: Some(Relationship::DependencyOf),
                ..node("A")
            }]),
            descendent: None,
        }]
        .roots();

        assert_eq!(
            result,
            vec![Node {
                base: base("A"),
                relationship: Some(Relationship::DependencyOf),
                ancestor: Some(vec![]),
                descendent: None,
            }]
        );
    }

    #[test]
    fn nested() {
        let result = vec![Node {
            ancestor: Some(vec![Node {
                base: base("AA"),
                relationship: Some(Relationship::DependencyOf),
                ancestor: Some(vec![Node {
                    ancestor: Some(vec![]),
                    relationship: Some(Relationship::DependencyOf),
                    ..node("A")
                }]),
                descendent: None,
            }]),
            ..node("AAA")
        }]
        .roots();

        assert_eq!(
            result,
            vec![Node {
                base: base("A"),
                relationship: Some(Relationship::DependencyOf),
                ancestor: Some(vec![]),
                descendent: None,
            }]
        );
    }
}
