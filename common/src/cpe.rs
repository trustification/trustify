use cpe::{
    cpe::Cpe as _,
    uri::{OwnedUri, Uri},
};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Cpe {
    uri: OwnedUri,
}

impl Display for Cpe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.uri, f)
    }
}

#[derive(Clone, Debug)]
pub enum Component {
    Any,
    NotApplicable,
    Value(String),
}

#[derive(Clone, Debug)]
pub enum Language {
    Any,
    Language(String),
}

pub enum CpeType {
    Any,
    Hardware,
    OperatingSystem,
    Application,
    Empty,
}

impl From<cpe::cpe::CpeType> for CpeType {
    fn from(value: cpe::cpe::CpeType) -> Self {
        match value {
            cpe::cpe::CpeType::Any => Self::Any,
            cpe::cpe::CpeType::Hardware => Self::Hardware,
            cpe::cpe::CpeType::OperatingSystem => Self::OperatingSystem,
            cpe::cpe::CpeType::Application => Self::Application,
            cpe::cpe::CpeType::Empty => Self::Empty,
        }
    }
}

impl From<cpe::cpe::Language> for Language {
    fn from(value: cpe::cpe::Language) -> Self {
        match value {
            cpe::cpe::Language::Any => Self::Any,
            cpe::cpe::Language::Language(lang) => Self::Language(lang.into_string()),
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

impl Cpe {
    pub fn part(&self) -> CpeType {
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

    pub fn language(&self) -> Language {
        self.uri.language().clone().into()
    }
}

impl Debug for Cpe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.uri, f)
    }
}

impl From<Uri<'_>> for Cpe {
    fn from(uri: Uri) -> Self {
        Self {
            uri: uri.to_owned(),
        }
    }
}

impl From<OwnedUri> for Cpe {
    fn from(uri: OwnedUri) -> Self {
        Self { uri }
    }
}

impl FromStr for Cpe {
    type Err = <OwnedUri as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            uri: OwnedUri::from_str(s)?,
        })
    }
}
