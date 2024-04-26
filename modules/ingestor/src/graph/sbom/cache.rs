use crate::graph::error::Error;
use crate::graph::package::qualified_package::QualifiedPackageContext;
use crate::graph::Graph;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::rc::Rc;
use tracing::instrument;
use trustify_common::db::Transactional;
use trustify_common::purl::Purl;

pub struct PackageCache<'a> {
    cache: HashMap<Purl, Rc<Result<QualifiedPackageContext<'a>, Error>>>,
    graph: &'a Graph,
    tx: &'a Transactional,
    hits: usize,
}

impl<'a> Debug for PackageCache<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackageCache")
            .field("cache", &self.cache.len())
            .field("hits", &self.hits)
            .finish()
    }
}

impl<'a> PackageCache<'a> {
    pub fn new(capacity: usize, graph: &'a Graph, tx: &'a Transactional) -> Self {
        Self {
            cache: HashMap::with_capacity(capacity),
            graph,
            tx,
            hits: 0,
        }
    }

    #[instrument]
    pub async fn lookup(&mut self, purl: &Purl) -> Rc<Result<QualifiedPackageContext<'a>, Error>> {
        match self.cache.entry(purl.clone()) {
            Entry::Occupied(entry) => {
                self.hits += 1;
                entry.get().clone()
            }
            Entry::Vacant(entry) => {
                let result = self.graph.ingest_qualified_package(purl, &self.tx).await;
                entry.insert(Rc::new(result)).clone()
            }
        }
    }
}
