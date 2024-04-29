use crate::graph::package::qualified_package::QualifiedPackageContext;
use crate::graph::{error::Error, package::PackageContext};
use sea_orm::{ConnectionTrait, EntityTrait};
use std::collections::{BTreeMap, HashMap, HashSet};
use trustify_common::purl::Purl;
use trustify_entity::package;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PackageLevel {
    r#type: String,
    namespace: Option<String>,
    name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct VersionLevel(String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct QualifierLevel(BTreeMap<String, String>);

fn split(purl: Purl) -> (PackageLevel, VersionLevel, QualifierLevel) {
    (
        PackageLevel {
            r#type: purl.ty,
            namespace: purl.namespace,
            name: purl.name,
        },
        VersionLevel(purl.version.unwrap_or_default()),
        QualifierLevel(BTreeMap::from_iter(purl.qualifiers)),
    )
}

pub struct Creator {
    scheduled: HashMap<PackageLevel, HashMap<VersionLevel, Vec<QualifierLevel>>>,
}

impl Creator {
    pub fn new() -> Self {
        Self {
            scheduled: Default::default(),
        }
    }

    fn add(&mut self, purl: Purl) {
        let (package, version, qualifier) = split(purl);
        self.scheduled
            .entry(package)
            .or_default()
            .entry(version)
            .or_default()
            .push(qualifier);
    }

    pub async fn create<'g, C>(
        self,
        db: C,
    ) -> Result<HashMap<Purl, QualifiedPackageContext<'g>>, Error>
    where
        C: ConnectionTrait,
    {
        // insert all packages

        // let packages =

        // insert all package versions
        // insert all qualified packages
        // return result
        todo!()
    }
}
