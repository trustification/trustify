use serde::{Deserialize, Serialize};
use crate::purl::Purl;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Dependencies {
    root: Purl,
    direct_dependencies: Vec<Purl>,

}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransitiveDependencies {
    root: Purl,
    direct_dependencies: Vec<TransitiveDependencies>,
}