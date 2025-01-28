use std::collections::HashSet;
use trustify_common::{cpe::Cpe, db::query::Query, purl::Purl};
use trustify_entity::relationship::Relationship;

#[derive(Copy, Clone, Debug)]
pub enum ComponentReference<'a> {
    /// The ID of the component.
    ///
    /// This is the ID provided by the document. For CycloneDX, this is the `bom-ref`.
    Id(&'a str),
    /// The name of the component
    Name(&'a str),
    /// A PURL of the component
    Purl(&'a Purl),
    /// A CPE of the component
    Cpe(&'a Cpe),
}

impl<'a> From<&'a Cpe> for ComponentReference<'a> {
    fn from(value: &'a Cpe) -> Self {
        Self::Cpe(value)
    }
}

impl<'a> From<&'a Purl> for ComponentReference<'a> {
    fn from(value: &'a Purl) -> Self {
        Self::Purl(value)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum GraphQuery<'a> {
    Component(ComponentReference<'a>),
    Query(&'a Query),
}

impl<'a> From<ComponentReference<'a>> for GraphQuery<'a> {
    fn from(reference: ComponentReference<'a>) -> Self {
        Self::Component(reference)
    }
}

impl<'a> From<&'a Cpe> for GraphQuery<'a> {
    fn from(value: &'a Cpe) -> Self {
        Self::Component(ComponentReference::Cpe(value))
    }
}

impl<'a> From<&'a Purl> for GraphQuery<'a> {
    fn from(value: &'a Purl) -> Self {
        Self::Component(ComponentReference::Purl(value))
    }
}

impl<'a> From<&'a Query> for GraphQuery<'a> {
    fn from(query: &'a Query) -> Self {
        Self::Query(query)
    }
}

/// Options when querying the graph.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct QueryOptions {
    #[serde(default)]
    pub ancestors: u64,
    #[serde(default)]
    pub descendants: u64,
    #[serde(default)]
    pub relationships: HashSet<Relationship>,
}

impl QueryOptions {
    pub fn any() -> Self {
        Self {
            ancestors: u64::MAX,
            descendants: u64::MAX,
            ..Default::default()
        }
    }

    pub fn ancestors() -> Self {
        Self {
            ancestors: u64::MAX,
            ..Default::default()
        }
    }

    pub fn descendants() -> Self {
        Self {
            descendants: u64::MAX,
            ..Default::default()
        }
    }
}

impl From<()> for QueryOptions {
    fn from(_: ()) -> Self {
        Self::default()
    }
}
