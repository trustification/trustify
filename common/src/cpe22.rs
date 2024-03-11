use cpe::component::OwnedComponent;
use cpe::cpe::{Cpe, CpeType};
use cpe::uri::{OwnedUri, Uri};
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone)]
pub struct Cpe22 {
    uri: cpe::uri::OwnedUri,
}

#[derive(Clone, Debug)]
pub enum Component {
    Any,
    NotApplicable,
    Value(String),
}

pub enum Cpe22Type {
    Any,
    Hardware,
    OperatingSystem,
    Application,
}

impl From<CpeType> for Cpe22Type {
    fn from(value: CpeType) -> Self {
        match value {
            CpeType::Any => Self::Any,
            CpeType::Hardware => Self::Hardware,
            CpeType::OperatingSystem => Self::OperatingSystem,
            CpeType::Application => Self::Application,
        }
    }
}

impl From<cpe::component::Component<'_>> for Component {
    fn from(value: cpe::component::Component<'_>) -> Self {
        match value {
            cpe::component::Component::Any => Self::Any,
            cpe::component::Component::NotApplicable => Self::NotApplicable,
            cpe::component::Component::Value(inner) => Self::Value(inner.to_string()),
        }
    }
}

impl Cpe22 {
    pub fn part(&self) -> Cpe22Type {
        self.uri.part().into()
    }

    pub fn vendor(&self) -> Component {
        self.uri.vendor().into()
    }

    pub fn product(&self) -> Component {
        self.uri.product().into()
    }

    pub fn version(&self) -> Component {
        self.uri.version().into()
    }

    pub fn update(&self) -> Component {
        self.uri.update().into()
    }

    pub fn edition(&self) -> Component {
        self.uri.edition().into()
    }
}

impl Debug for Cpe22 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.uri, f)
    }
}

impl From<cpe::uri::Uri<'_>> for Cpe22 {
    fn from(uri: Uri) -> Self {
        Self {
            uri: uri.to_owned(),
        }
    }
}

impl From<cpe::uri::OwnedUri> for Cpe22 {
    fn from(uri: OwnedUri) -> Self {
        Self { uri }
    }
}
