use super::*;

impl AnalysisService {
    pub fn render_dot(&self, sbom: &str) -> Option<String> {
        use std::fmt::Write;

        struct Renderer<'a> {
            data: &'a mut String,
        }

        impl Visitor for Renderer<'_> {
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

            fn edge(
                &mut self,
                source: &PackageNode,
                relationship: Relationship,
                target: &PackageNode,
            ) {
                let _ = writeln!(
                    self.data,
                    r#""{source}" -> "{target}" [label="{label}"]"#,
                    source = escape(&source.node_id),
                    target = escape(&target.node_id),
                    label = escape(&relationship.to_string())
                );
            }
        }

        let mut data = String::new();

        data.push_str(
            r#"
digraph {
"#,
        );

        if self.walk(sbom, Renderer { data: &mut data }) {
            data.push_str(
                r#"
}
"#,
            );

            Some(data)
        } else {
            None
        }
    }
}

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

#[cfg(test)]
mod test {

    #[test]
    fn escape() {
        assert_eq!(super::escape("foo\"bar\nbaz"), r#"foo\"bar\nbaz"#);
    }
}
