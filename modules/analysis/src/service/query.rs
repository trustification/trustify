use trustify_common::db::query::Query;
use trustify_common::{cpe::Cpe, purl::Purl};

#[derive(Copy, Clone, Debug)]
pub enum ComponentReference<'a> {
    Name(&'a str),
    Purl(&'a Purl),
    Cpe(&'a Cpe),
}

impl<'a> From<&'a str> for ComponentReference<'a> {
    fn from(value: &'a str) -> Self {
        Self::Name(value)
    }
}

impl<'a> From<&'a String> for ComponentReference<'a> {
    fn from(value: &'a String) -> Self {
        Self::Name(value)
    }
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

impl<'a> From<&'a str> for GraphQuery<'a> {
    fn from(value: &'a str) -> Self {
        Self::Component(ComponentReference::Name(value))
    }
}

impl<'a> From<&'a String> for GraphQuery<'a> {
    fn from(value: &'a String) -> Self {
        Self::Component(ComponentReference::Name(value))
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
