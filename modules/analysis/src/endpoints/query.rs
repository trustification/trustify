use crate::{
    Error,
    service::{ComponentReference, GraphQuery},
};
use std::str::FromStr;
use trustify_common::{cpe::Cpe, purl::Purl};

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum OwnedComponentReference {
    Name(String),
    Purl(Purl),
    Cpe(Cpe),
}

impl<'a> From<&'a OwnedComponentReference> for ComponentReference<'a> {
    fn from(value: &'a OwnedComponentReference) -> Self {
        match value {
            OwnedComponentReference::Name(value) => ComponentReference::Name(value),
            OwnedComponentReference::Purl(value) => ComponentReference::Purl(value),
            OwnedComponentReference::Cpe(value) => ComponentReference::Cpe(value),
        }
    }
}

impl<'a> From<&'a OwnedComponentReference> for GraphQuery<'a> {
    fn from(value: &'a OwnedComponentReference) -> Self {
        GraphQuery::Component(value.into())
    }
}

impl TryFrom<&str> for OwnedComponentReference {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // TODO - this currently does not identify a node_id (which might entail expensive sbom_node lookup)
        if value.starts_with("pkg:") {
            let purl = Purl::from_str(value).map_err(Error::Purl)?;
            Ok(OwnedComponentReference::Purl(purl))
        } else if value.starts_with("cpe:") {
            let cpe = Cpe::from_str(value).map_err(Error::Cpe)?;
            Ok(OwnedComponentReference::Cpe(cpe))
        } else {
            Ok(OwnedComponentReference::Name(value.to_string()))
        }
    }
}
