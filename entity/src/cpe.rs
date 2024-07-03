use cpe::{error::CpeError, uri::Uri};
use sea_orm::entity::prelude::*;
use sea_orm::{NotSet, Set};
use std::fmt::{Debug, Display, Formatter};
use trustify_common::cpe::Component::Value;
use trustify_common::cpe::{Component, Cpe, CpeType};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cpe")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub part: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub update: Option<String>,
    pub edition: Option<String>,
    pub language: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom_package_cpe_ref::Entity",
        from = "Column::Id",
        to = "super::sbom_package_cpe_ref::Column::CpeId"
    )]
    SbomPackage,
}

impl Related<super::sbom_package_cpe_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomPackage.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Display for Model {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut cpe = cpe::uri::Uri::new();
        self.part.as_ref().map(|part| cpe.set_part(part));
        self.vendor.as_ref().map(|vendor| cpe.set_vendor(vendor));
        self.product
            .as_ref()
            .map(|product| cpe.set_product(product));
        self.version
            .as_ref()
            .map(|version| cpe.set_version(version));
        self.update.as_ref().map(|update| cpe.set_update(update));
        self.edition
            .as_ref()
            .map(|edition| cpe.set_edition(edition));
        self.language
            .as_ref()
            .map(|language| cpe.set_language(language));

        Display::fmt(&cpe, f)
    }
}

impl ActiveModel {
    pub fn from_cpe(cpe: Cpe) -> Self {
        ActiveModel {
            id: Default::default(),
            part: match cpe.part() {
                CpeType::Any => Set(Some("*".to_string())),
                CpeType::Hardware => Set(Some("h".to_string())),
                CpeType::OperatingSystem => Set(Some("o".to_string())),
                CpeType::Application => Set(Some("a".to_string())),
                CpeType::Empty => Set(None),
            },
            vendor: match cpe.vendor() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            product: match cpe.product() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            version: match cpe.version() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            update: match cpe.update() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            edition: match cpe.edition() {
                Component::Any => Set(Some("*".to_string())),
                Component::NotApplicable => NotSet,
                Value(inner) => Set(Some(inner)),
            },
            language: Set(None),
        }
    }
}

impl From<Cpe> for ActiveModel {
    fn from(value: Cpe) -> Self {
        Self::from_cpe(value)
    }
}

/// A serializable (data only, no id) variant of the CPE, as stored in the database.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CpeDto {
    pub part: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub update: Option<String>,
    pub edition: Option<String>,
    pub language: Option<String>,
}

macro_rules! apply {
    ($c: expr, $v:expr => $n:ident) => {
        if let Some($n) = &$v.$n {
            $c.$n($n);
        }
    };
    ($c: expr, $v:expr => $n:ident, $($m:ident),+) => {
        apply!($c, $v => $n );
        apply!($c, $v => $($m),+)
    };
}

macro_rules! apply_fix {
    ($c: expr, $v:expr => $n:ident) => {
        if let Some($n) = &$v.$n {
            if $n == "*" {
                $c.$n("");
            } else {
                $c.$n($n);
            }

        }
    };
    ($c: expr, $v:expr => $n:ident, $($m:tt),+) => {
        apply_fix!($c, $v => $n );
        apply_fix!($c, $v => $($m),+)
    };
}

/// Convert from the DTO into an actual one
impl TryFrom<CpeDto> for Cpe {
    type Error = CpeError;

    fn try_from(value: CpeDto) -> Result<Self, Self::Error> {
        let mut cpe = Uri::builder();

        apply!(cpe, value => part, language);
        apply_fix!(cpe, value => vendor, product, version, update, edition);

        cpe.validate().map(|cpe| cpe.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sea_orm::TryIntoModel;
    use std::str::FromStr;

    use test_log::test;
    use trustify_common::cpe::Cpe;

    // currently broken due to: https://github.com/KenDJohnson/cpe-rs/issues/9
    #[ignore]
    #[test]
    fn test_roundtrip() {
        // from here we start
        const CPE: &str = "cpe:/a:redhat:openshift_container_storage:4.8::el8";

        // parse into a CPE
        let cpe = Cpe::from_str(CPE).unwrap();

        let id = Uuid::new_v4();

        // turn it into a model to be inserted
        let model = ActiveModel {
            id: Set(id),
            ..cpe.into()
        };

        log::info!("cpe: {model:#?}");

        // now turn into a model and destructure to ensure we don't miss any new fields
        let Model {
            id: _,
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
        } = model.try_into_model().unwrap();

        // turn it into a DTO a read from the aggregate fields

        let dto = CpeDto {
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
        };

        // and turn it back into a CPE

        let cpe: Cpe = dto.try_into().expect("must be able to build cpe");

        // ensure it's the same as the original one

        assert_eq!(CPE, format!("{cpe:0}"));
    }
}
