use crate::{model::PackageNode, service::Visitor};
use trustify_entity::relationship::Relationship;

fn escape(id: &str) -> String {
    let mut escaped = String::with_capacity(id.len());

    for ch in id.chars() {
        match ch {
            '"' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '\n' => {
                escaped.push_str("\\n");
            }
            _ => escaped.push(ch),
        }
    }

    escaped
}

use std::fmt::Write;

pub struct Renderer {
    data: String,
}

impl Renderer {
    pub fn new() -> Self {
        Self {
            data: r#"
digraph {
"#
            .to_string(),
        }
    }
}

impl Visitor for Renderer {
    type Output = (String, String);

    fn node(&mut self, node: &PackageNode) {
        let _ = writeln!(
            self.data,
            r#""{id}" [label="{label}"]"#,
            id = escape(&node.node_id),
            label = escape(&format!(
                "{name} / {version}: {id}",
                name = node.name,
                version = node.version,
                id = node.node_id
            ))
        );
    }

    fn edge(&mut self, source: &PackageNode, relationship: Relationship, target: &PackageNode) {
        let _ = writeln!(
            self.data,
            r#""{source}" -> "{target}" [label="{label}"]"#,
            source = escape(&source.node_id),
            target = escape(&target.node_id),
            label = escape(&relationship.to_string())
        );
    }

    fn complete(mut self) -> Self::Output {
        self.data.push_str(
            r#"
}
"#,
        );

        (self.data, "text/vnd.graphviz".to_string())
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn escape() {
        assert_eq!(super::escape("foo\"bar\nbaz"), r#"foo\"bar\nbaz"#);
    }
}
