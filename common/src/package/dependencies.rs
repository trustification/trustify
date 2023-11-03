use crate::purl::Purl;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Dependencies {
    root: Purl,
    direct_dependencies: Vec<Purl>,
}

impl From<(Purl, Vec<Purl>)> for Dependencies {
    fn from((root, direct_dependencies): (Purl, Vec<Purl>)) -> Self {
        Self {
            root,
            direct_dependencies,
        }
    }
}
