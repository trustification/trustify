mod system;

use packageurl::PackageUrl;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use sea_orm_migration::MigratorTrait;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

#[derive(Clone, PartialEq)]
pub struct Purl<'a> {
    pub package_url: PackageUrl<'a>,
}

impl Hash for Purl<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.package_url.to_string().as_bytes())
    }
}

impl Eq for Purl<'_> {}

impl Display for Purl<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.package_url.to_string())
    }
}

impl Debug for Purl<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.package_url.to_string())
    }
}

impl<'a> From<&'a str> for Purl<'a> {
    fn from(value: &'a str) -> Self {
        Purl {
            package_url: PackageUrl::from_str(value).unwrap(),
        }
    }
}

impl<'a> From<&&'a str> for Purl<'a> {
    fn from(value: &&'a str) -> Self {
        Purl {
            package_url: PackageUrl::from_str(value).unwrap(),
        }
    }
}

impl<'a> From<PackageUrl<'a>> for Purl<'a> {
    fn from(value: PackageUrl<'a>) -> Self {
        Self { package_url: value }
    }
}

#[derive(Clone, Debug)]
pub struct PackageTree<'p> {
    purl: Purl<'p>,
    dependencies: Vec<PackageTree<'p>>,
}
