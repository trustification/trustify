mod graphviz;

use super::*;
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, ToSchema)]
pub enum Renderer {
    #[serde(rename = "gv", alias = "dot")]
    Graphviz,
}

impl AnalysisService {
    pub fn render(&self, sbom: &str, renderer: Renderer) -> Option<(String, String)> {
        match renderer {
            Renderer::Graphviz => self.walk(sbom, graphviz::Renderer::new()),
        }
    }
}
